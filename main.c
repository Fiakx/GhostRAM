#include "raylib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#define SCREEN_WIDTH 1400
#define SCREEN_HEIGHT 900
#define BYTES_PER_ROW 16
#define SIDEBAR_WIDTH 350

typedef struct { long long start; long long end; } RAMRange;
typedef struct { long long offset; int len; bool found; bool searching; float progress; char query[64]; } GlobalSearch;
typedef struct { long long start; long long end; char label[32]; } DynamicZone;

RAMRange ramRanges[16];
int ramRangeCount = 0;
DynamicZone dynZones[200];
int dynZoneCount = 0;

GlobalSearch gSearch = {0, 0, false, false, 0.0f, ""};
long long viewOffset = 0;
int mem_fd_global;
float sidebarScrollY = 0;
char searchInput[64] = "\0";
int letterCount = 0;

pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;

// dans /proc/kcore, la RAM est souvent mappée à un offset très haut sur 64bit
// on commence souvent à 0 pour voir le header ELF de kcore
void MapSystemRAM() {
    FILE *f = fopen("/proc/iomem", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f) && ramRangeCount < 16) {
        if (strstr(line, "system RAM")) {
            sscanf(line, "%llx-%llx", &ramRanges[ramRangeCount].start, &ramRanges[ramRangeCount].end);
            ramRangeCount++;
        }
    }
    fclose(f);
}

void* GlobalSearchThread(void* arg) {
    gSearch.searching = true;
    gSearch.found = false;
    int qLen = strlen(gSearch.query);
    if (qLen == 0) { gSearch.searching = false; return NULL; }

    size_t bufSize = 1024 * 1024 * 2; // 2mb buffer
    unsigned char *buffer = malloc(bufSize);

    // parcourt les plages trouvées dans iomem
    for (int r = 0; r < ramRangeCount; r++) {
        long long current = ramRanges[r].start;
        while (current < ramRanges[r].end && gSearch.searching) {
            // pread =crucial pour ne pas "perturber" l'affichage principal
            ssize_t n = pread(mem_fd_global, buffer, bufSize, current);
            if (n <= 0) break;

            for (int i = 0; i < n - qLen; i++) {
                if (memcmp(&buffer[i], gSearch.query, qLen) == 0) {
                    pthread_mutex_lock(&data_mutex);
                    gSearch.offset = current + i;
                    gSearch.len = qLen;
                    gSearch.found = true;
                    gSearch.searching = false;
                    viewOffset = (gSearch.offset / BYTES_PER_ROW) * BYTES_PER_ROW;
                    pthread_mutex_unlock(&data_mutex);
                    free(buffer); return NULL;
                }
            }
            current += (n - qLen); // on recule un peu pour ne pas rater un mot coupé
            gSearch.progress = (float)r / ramRangeCount;
        }
    }
    gSearch.searching = false;
    free(buffer); return NULL;
}

void* ZoneDiscoveryThread(void* arg) {
    unsigned char chunk[4096];
    long long addr = (ramRangeCount > 0) ? ramRanges[0].start : 0;
    int zeroCounter = 0;
    bool inZone = false;
    long long zoneStart = 0;

    while (dynZoneCount < 200) {
        ssize_t n = pread(mem_fd_global, chunk, 4096, addr);
        if (n <= 0) { addr += 4096; continue; }

        for (int i = 0; i < n; i++) {
            if (chunk[i] != 0) {
                if (!inZone) { zoneStart = addr + i; inZone = true; }
                zeroCounter = 0;
            } else if (inZone) {
                zeroCounter++;
                if (zeroCounter > 512) {
                    pthread_mutex_lock(&data_mutex);
                    dynZones[dynZoneCount].start = zoneStart;
                    dynZones[dynZoneCount].end = (addr + i) - 512;
                    sprintf(dynZones[dynZoneCount].label, "zone RAM #%d", dynZoneCount + 1);
                    dynZoneCount++;
                    pthread_mutex_unlock(&data_mutex);
                    inZone = false; zeroCounter = 0;
                }
            }
        }
        addr += 4096;
        usleep(1000); // pr ne pas saturer le CPU
    }
    return NULL;
}

int main() {
    MapSystemRAM();
    mem_fd_global = open("/proc/kcore", O_RDONLY);
    if (mem_fd_global == -1) {
        perror("erreur open /proc/kcore (SUDO requis)");
        return 1;
    }

    if (ramRangeCount > 0) viewOffset = ramRanges[0].start;

    pthread_t tZone, tSearch;
    pthread_create(&tZone, NULL, ZoneDiscoveryThread, NULL);

    InitWindow(SCREEN_WIDTH, SCREEN_HEIGHT, "analyseur RAM - GhostRAM");
    SetTargetFPS(60);

    unsigned char page[BYTES_PER_ROW * 35];

    while (!WindowShouldClose()) {
        // clavier
        int key = GetCharPressed();
        while (key > 0) {
            if (letterCount < 63) { searchInput[letterCount++] = (char)key; searchInput[letterCount] = '\0'; }
            key = GetCharPressed();
        }
        if (IsKeyPressed(KEY_BACKSPACE) && letterCount > 0) searchInput[--letterCount] = '\0';
        
        if (IsKeyPressed(KEY_ENTER) && !gSearch.searching) {
            strcpy(gSearch.query, searchInput);
            pthread_create(&tSearch, NULL, GlobalSearchThread, NULL);
        }

        // nav souris
        Vector2 mPos = GetMousePosition();
        if (mPos.x > SCREEN_WIDTH - SIDEBAR_WIDTH) {
            sidebarScrollY += GetMouseWheelMove() * 45;
        } else {
            viewOffset += GetMouseWheelMove() * BYTES_PER_ROW * -8;
        }
        if (viewOffset < 0) viewOffset = 0;

        pread(mem_fd_global, page, sizeof(page), viewOffset);

        BeginDrawing();
        ClearBackground((Color){10, 12, 18, 255});

        // hexa
        for (int i = 0; i < 35; i++) {
            long long off = viewOffset + (i * BYTES_PER_ROW);
            int y = 100 + (i * 22);
            DrawText(TextFormat("%012llX", off), 15, y, 18, DARKGREEN);

            for (int j = 0; j < BYTES_PER_ROW; j++) {
                long long pos = off + j;
                unsigned char b = page[i * BYTES_PER_ROW + j];
                bool isResult = (gSearch.found && pos >= gSearch.offset && pos < gSearch.offset + gSearch.len);

                int xHex = 190 + j * 35;
                if (isResult) DrawRectangle(xHex - 2, y, 32, 20, MAROON);
                DrawText(TextFormat("%02X", b), xHex, y, 18, (isResult ? YELLOW : (b == 0 ? DARKGRAY : WHITE)));

                int xAsc = 780 + j * 16;
                char c = (b >= 32 && b <= 126) ? (char)b : '.';
                if (isResult) DrawRectangle(xAsc, y, 14, 20, MAROON);
                DrawText(TextFormat("%c", c), xAsc, y, 18, (isResult ? YELLOW : (b == 0 ? DARKGRAY : SKYBLUE)));
            }
        }

        // droite
        DrawRectangle(SCREEN_WIDTH - SIDEBAR_WIDTH, 0, SIDEBAR_WIDTH, SCREEN_HEIGHT, (Color){20, 22, 30, 255});
        DrawLine(SCREEN_WIDTH - SIDEBAR_WIDTH, 0, SCREEN_WIDTH - SIDEBAR_WIDTH, SCREEN_HEIGHT, DARKGRAY);
        DrawText(TextFormat("ZONES DYNAMIQUES (%d)", dynZoneCount), SCREEN_WIDTH - SIDEBAR_WIDTH + 20, 25, 18, GOLD);

        BeginScissorMode(SCREEN_WIDTH - SIDEBAR_WIDTH, 70, SIDEBAR_WIDTH, SCREEN_HEIGHT - 70);
        for (int i = 0; i < dynZoneCount; i++) {
            Rectangle r = { SCREEN_WIDTH - SIDEBAR_WIDTH + 10, 80 + i * 65 + sidebarScrollY, SIDEBAR_WIDTH - 20, 60 };
            bool hover = CheckCollisionPointRec(mPos, r);
            DrawRectangleRec(r, hover ? (Color){45, 55, 80, 255} : (Color){30, 32, 45, 255});
            if (hover && IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) viewOffset = dynZones[i].start;
            
            DrawText(dynZones[i].label, r.x + 10, r.y + 10, 16, WHITE);
            DrawText(TextFormat("0x%llX", dynZones[i].start), r.x + 10, r.y + 35, 13, LIME);
        }
        EndScissorMode();

        // haut
        DrawRectangle(0, 0, SCREEN_WIDTH - SIDEBAR_WIDTH, 80, (Color){10, 12, 18, 240});
        DrawText("RECHERCHE :", 20, 30, 20, LIGHTGRAY);
        DrawText(searchInput, 160, 30, 20, GREEN);
        
        if (gSearch.searching) {
            DrawRectangle(160, 55, (int)(300 * gSearch.progress), 5, LIME);
            DrawText("scan en cours...", 470, 30, 16, LIME);
        } else if (gSearch.found) {
            DrawText("TROUVÉ !", 470, 30, 16, GOLD);
        }

        EndDrawing();
    }

    close(mem_fd_global);
    CloseWindow();
    return 0;
}
