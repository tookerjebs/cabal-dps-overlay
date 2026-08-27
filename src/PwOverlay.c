/* Cabal Online overlay. Npcap capture. No writes to the game process.
 * Drag the left grip. Click the strip for Lock / Reset.
 * F8 click-through. F9 reset. Hidden if Cabal is minimized.
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "ingest.h"
#include "skill_names.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#define TARGET_EXE L"CabalMain.exe"
#define OVERLAY_CLASS L"PlayCabalWireOverlay"
#define POLL_MS 8u
#define UI_FRAME_MS 8ull
#define STRIP_W 380
#define STRIP_PAD_Y 3
#define STRIP_ROW_H 26
#define STRIP_H (STRIP_PAD_Y + STRIP_ROW_H * 2 + STRIP_PAD_Y)
#define GRIP_W 18
#define STRIP_LABEL_LEFT (GRIP_W + 8)
#define STRIP_RIGHT (STRIP_W - 8)
#define STRIP_HIT_W 96
#define STRIP_DPS_LEFT (STRIP_W - 148)
#define PANEL_H 32
#define DETAIL_H 40
#define GRAPH_LABEL_H 18
#define GRAPH_H 72
#define GRAPH_GAP 8
#define SKILL_HEAD_H 16
#define SKILL_LINE_H 16
#define BTN_H 18
#define HOTKEY_RESET 1
#define HOTKEY_CLICK 2

typedef struct {
    DWORD pid;
    HWND best;
    LONG best_area;
} FindWnd;

static HWND g_hwnd;
static HWND g_game;
static HFONT g_font;
static HFONT g_font_sm;
static HANDLE g_singleton;
static int g_dragging;
static int g_has_rel;
static int g_rel_x;
static int g_rel_y;
static int g_click_through;
static int g_visible;
static int g_expanded;
static int g_notice;
static unsigned g_last_parts_n;
static int g_placed;
static int g_placed_x;
static int g_placed_y;
static int g_placed_w;
static int g_placed_h;
static uint64_t g_last_paint_request;
static PwMeterSnap g_last_snap;

static int
overlay_w(void)
{
    return STRIP_W;
}

static int
skill_block_h(void)
{
    return SKILL_HEAD_H + (int)PW_SKILL_UI * SKILL_LINE_H;
}

static int
after_split(void)
{
    int y = 6;
    if (g_notice) {
        y += 22;
    }
    if (g_last_parts_n > 1) {
        y += DETAIL_H;
    }
    return y;
}

static int
graph_block_h(void)
{
    return GRAPH_LABEL_H + GRAPH_H;
}

static int
expand_extra(void)
{
    return after_split() + graph_block_h() + GRAPH_GAP + skill_block_h() + 4 + PANEL_H;
}

static int
overlay_h(void)
{
    return g_expanded ? (STRIP_H + expand_extra()) : STRIP_H;
}

static uint64_t
now_ms(void)
{
    return GetTickCount64();
}

static DWORD
find_pid(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    DWORD pid = 0;

    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, TARGET_EXE) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static BOOL CALLBACK
enum_game_wnd(HWND hwnd, LPARAM lp)
{
    FindWnd *f = (FindWnd *)lp;
    DWORD pid = 0;
    RECT rc;
    LONG area;
    WCHAR cls[64];

    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != f->pid || hwnd == g_hwnd) {
        return TRUE;
    }
    if (!GetClassNameW(hwnd, cls, 64) || lstrcmpiW(cls, OVERLAY_CLASS) == 0) {
        return TRUE;
    }
    if (!GetWindowRect(hwnd, &rc)) {
        return TRUE;
    }
    area = (rc.right - rc.left) * (rc.bottom - rc.top);
    if (area > f->best_area && (rc.right - rc.left) > 200 && (rc.bottom - rc.top) > 200) {
        f->best_area = area;
        f->best = hwnd;
    }
    return TRUE;
}

static HWND
find_game_window(DWORD pid)
{
    FindWnd f;
    if (!pid) {
        return NULL;
    }
    f.pid = pid;
    f.best = NULL;
    f.best_area = 0;
    EnumWindows(enum_game_wnd, (LPARAM)&f);
    return f.best;
}

static int
game_is_showing(HWND game)
{
    if (!game || !IsWindow(game) || !IsWindowVisible(game) || IsIconic(game)) {
        return 0;
    }
    return 1;
}

static int
game_client_screen(HWND game, RECT *out)
{
    RECT cr;
    POINT tl;

    if (!GetClientRect(game, &cr)) {
        return 0;
    }
    tl.x = cr.left;
    tl.y = cr.top;
    if (!ClientToScreen(game, &tl)) {
        return 0;
    }
    out->left = tl.x;
    out->top = tl.y;
    out->right = tl.x + (cr.right - cr.left);
    out->bottom = tl.y + (cr.bottom - cr.top);
    return (out->right - out->left) > 100 && (out->bottom - out->top) > 100;
}

static void
set_click_through(HWND hwnd, int on)
{
    LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    g_click_through = on ? 1 : 0;
    if (on) {
        ex |= WS_EX_TRANSPARENT;
    } else {
        ex &= ~WS_EX_TRANSPARENT;
    }
    SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex);
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

static void
save_rel_from_window(HWND overlay, HWND game)
{
    RECT ov, cl;

    if (!GetWindowRect(overlay, &ov) || !game_client_screen(game, &cl)) {
        return;
    }
    g_rel_x = ov.left - cl.left;
    g_rel_y = ov.top - cl.top;
    g_has_rel = 1;
}

static void
place_overlay(HWND overlay, HWND game)
{
    RECT cl;
    int x, y;
    int cw;

    if (g_dragging) {
        return;
    }

    if (game && !game_is_showing(game)) {
        if (g_visible) {
            ShowWindow(overlay, SW_HIDE);
            g_visible = 0;
        }
        g_placed = 0;
        return;
    }

    if (!game || !game_client_screen(game, &cl)) {
        if (!g_visible) {
            ShowWindow(overlay, SW_SHOWNOACTIVATE);
            g_visible = 1;
        }
        return;
    }

    cw = cl.right - cl.left;
    if (!g_has_rel) {
        g_rel_x = cw - overlay_w() - 14;
        g_rel_y = 18;
        g_has_rel = 1;
    }

    x = cl.left + g_rel_x;
    y = cl.top + g_rel_y;
    if (x < cl.left) {
        x = cl.left;
    }
    if (y < cl.top) {
        y = cl.top;
    }
    if (x + overlay_w() > cl.right) {
        x = cl.right - overlay_w();
    }
    if (y + overlay_h() > cl.bottom) {
        y = cl.bottom - overlay_h();
    }

    if (!g_placed ||
        g_placed_x != x ||
        g_placed_y != y ||
        g_placed_w != overlay_w() ||
        g_placed_h != overlay_h()) {
        SetWindowPos(overlay, HWND_TOPMOST, x, y, overlay_w(), overlay_h(),
                     SWP_NOACTIVATE);
        g_placed = 1;
        g_placed_x = x;
        g_placed_y = y;
        g_placed_w = overlay_w();
        g_placed_h = overlay_h();
    }
    if (!g_visible) {
        ShowWindow(overlay, SW_SHOWNOACTIVATE);
        g_visible = 1;
    }
}

static void
fmt_num(WCHAR *out, size_t n, uint64_t v)
{
    swprintf(out, n, L"%llu", (unsigned long long)v);
}

static void
fmt_compact(WCHAR *out, size_t n, uint64_t v)
{
    if (v < 10000ull) {
        swprintf(out, n, L"%llu", (unsigned long long)v);
        return;
    }
    if (v < 1000000ull) {
        uint64_t tenth = (v * 10ull + 50ull) / 1000ull;
        swprintf(out, n, L"%llu.%lluk", (unsigned long long)(tenth / 10ull),
                 (unsigned long long)(tenth % 10ull));
        return;
    }
    {
        uint64_t tenth = (v * 10ull + 50000ull) / 1000000ull;
        swprintf(out, n, L"%llu.%lluM", (unsigned long long)(tenth / 10ull),
                 (unsigned long long)(tenth % 10ull));
    }
}

static int
btn_top(void)
{
    return STRIP_H + after_split() + graph_block_h() + GRAPH_GAP + skill_block_h() + 4;
}

static void
utf8_to_wide(WCHAR *out, int n, const char *s)
{
    if (!out || n <= 0) {
        return;
    }
    out[0] = 0;
    if (!s || !s[0]) {
        return;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, out, n) <= 0) {
        out[0] = 0;
        return;
    }
    out[n - 1] = 0;
}

static void
skill_label(WCHAR *out, int n, uint32_t id)
{
    const char *name = pw_skill_name(id);
    if (name && name[0]) {
        utf8_to_wide(out, n, name);
        if (out[0]) {
            return;
        }
    }
    swprintf(out, n, L"Skill %u", (unsigned)id);
}

static void
draw_dmg_graph(HDC hdc, const uint64_t *g, const RECT *plot)
{
    HBRUSH bg = CreateSolidBrush(RGB(22, 24, 30));
    HBRUSH bar = CreateSolidBrush(RGB(80, 220, 140));
    uint64_t mx = 1;
    unsigned i;
    int w;
    int h;

    FillRect(hdc, plot, bg);
    w = plot->right - plot->left;
    h = plot->bottom - plot->top;
    if (w < 8 || h < 8) {
        DeleteObject(bg);
        DeleteObject(bar);
        return;
    }
    for (i = 0; i < PW_GRAPH_SECS; i++) {
        if (g[i] > mx) {
            mx = g[i];
        }
    }
    for (i = 0; i < PW_GRAPH_SECS; i++) {
        int x0 = plot->left + (int)((unsigned)w * i / PW_GRAPH_SECS);
        int x1 = plot->left + (int)((unsigned)w * (i + 1u) / PW_GRAPH_SECS);
        int bh = (int)((uint64_t)(h - 2) * g[i] / mx);
        RECT r;
        if (g[i] && bh < 1) {
            bh = 1;
        }
        r.left = x0 + 1;
        r.right = x1;
        r.bottom = plot->bottom - 1;
        r.top = r.bottom - bh;
        if (g[i] && r.right > r.left) {
            FillRect(hdc, &r, bar);
        }
    }
    DeleteObject(bg);
    DeleteObject(bar);
}

static void
btn_lock_rect(RECT *r)
{
    int top = btn_top();
    r->left = STRIP_LABEL_LEFT;
    r->top = top;
    r->right = STRIP_LABEL_LEFT + 64;
    r->bottom = top + BTN_H;
}

static void
btn_reset_rect(RECT *r)
{
    int top = btn_top();
    r->left = STRIP_LABEL_LEFT + 70;
    r->top = top;
    r->right = STRIP_LABEL_LEFT + 124;
    r->bottom = top + BTN_H;
}

static void
strip_row_y(RECT *r, int row)
{
    r->top = STRIP_PAD_Y + row * STRIP_ROW_H;
    r->bottom = r->top + STRIP_ROW_H;
}

static uint64_t
strip_skill_value(const PwMeterSnap *s)
{
    if (s->last_skill_total) {
        return s->last_skill_total;
    }
    return s->skill_total;
}

static void
request_repaint(HWND hwnd, uint64_t at)
{
    if (!g_last_paint_request || at - g_last_paint_request >= UI_FRAME_MS) {
        InvalidateRect(hwnd, NULL, FALSE);
        g_last_paint_request = at;
    }
}

static void
paint_overlay(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC target = BeginPaint(hwnd, &ps);
    HDC hdc = target;
    HDC buffer = NULL;
    HBITMAP back = NULL;
    HGDIOBJ old_bitmap = NULL;
    RECT rc, strip, grip, dpsrc, lab, val, lockr, resetr, fail;
    HBRUSH bg = CreateSolidBrush(RGB(16, 16, 20));
    HBRUSH gripb = CreateSolidBrush(RGB(36, 36, 42));
    HBRUSH btnb = CreateSolidBrush(RGB(40, 40, 48));
    WCHAR text[96];
    WCHAR nbuf[32];
    HFONT old;
    PwMeterSnap snap;
    uint64_t skill_value;

    pw_ingest_snap(&snap);
    if (snap.notice != g_notice || snap.last_parts_n != g_last_parts_n) {
        g_notice = snap.notice;
        g_last_parts_n = snap.last_parts_n;
        g_placed = 0;
    }
    g_notice = snap.notice;
    g_last_parts_n = snap.last_parts_n;
    skill_value = strip_skill_value(&snap);

    GetClientRect(hwnd, &rc);
    buffer = CreateCompatibleDC(target);
    if (buffer) {
        back = CreateCompatibleBitmap(target, rc.right - rc.left, rc.bottom - rc.top);
        if (back) {
            old_bitmap = SelectObject(buffer, back);
            hdc = buffer;
        } else {
            DeleteDC(buffer);
            buffer = NULL;
        }
    }
    FillRect(hdc, &rc, bg);
    SetBkMode(hdc, TRANSPARENT);
    old = (HFONT)SelectObject(hdc, g_font);

    strip = rc;
    strip.bottom = STRIP_H;
    grip = strip;
    grip.right = GRIP_W;
    FillRect(hdc, &grip, gripb);
    SetTextColor(hdc, RGB(120, 120, 128));
    DrawTextW(hdc, L"::", 2, &grip, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    strip_row_y(&lab, 0);
    lab.left = STRIP_LABEL_LEFT;
    lab.right = STRIP_RIGHT - STRIP_HIT_W - 8;
    val = lab;
    val.left = lab.right + 8;
    val.right = STRIP_RIGHT;
    SelectObject(hdc, g_font_sm);
    SetTextColor(hdc, RGB(136, 136, 144));
    if (snap.have_last_skill && snap.skill_id) {
        skill_label(text, 96, snap.skill_id);
        DrawTextW(hdc, text, -1, &lab,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    } else {
        DrawTextW(hdc, L"last skill", -1, &lab, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    SelectObject(hdc, g_font);
    SetTextColor(hdc, RGB(80, 220, 140));
    if (skill_value) {
        fmt_num(nbuf, 32, skill_value);
        DrawTextW(hdc, nbuf, -1, &val, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    } else {
        DrawTextW(hdc, L"0", -1, &val, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    }

    strip_row_y(&lab, 1);
    lab.left = STRIP_LABEL_LEFT;
    lab.right = STRIP_LABEL_LEFT + 44;
    val = lab;
    val.left = lab.right;
    val.right = STRIP_DPS_LEFT - 6;
    dpsrc.left = STRIP_DPS_LEFT;
    dpsrc.right = STRIP_RIGHT;
    dpsrc.top = lab.top;
    dpsrc.bottom = lab.bottom;
    SelectObject(hdc, g_font_sm);
    SetTextColor(hdc, RGB(136, 136, 144));
    DrawTextW(hdc, L"total", -1, &lab, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, g_font);
    SetTextColor(hdc, RGB(80, 220, 140));
    fmt_compact(nbuf, 32, snap.session_total);
    DrawTextW(hdc, nbuf, -1, &val, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SetTextColor(hdc, snap.in_combat ? RGB(80, 220, 140) : RGB(170, 174, 184));
    swprintf(text, 96, L"%llu dps", (unsigned long long)(snap.dps + 0.5));
    DrawTextW(hdc, text, -1, &dpsrc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    if (g_expanded) {
        int y = STRIP_H + 6;
        RECT split, split2;
        unsigned i;
        unsigned show;

        if (snap.notice) {
            fail.left = GRIP_W + 8;
            fail.top = y;
            fail.right = STRIP_W - 8;
            fail.bottom = y + 20;
            SelectObject(hdc, g_font_sm);
            SetTextColor(hdc, RGB(220, 140, 80));
            if (snap.notice == PW_NOTICE_NPCAP) {
                DrawTextW(hdc, L"Npcap missing. Install Npcap, then rerun.", -1, &fail,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            } else if (snap.notice == PW_NOTICE_KEYCHAIN) {
                DrawTextW(hdc, L"keychain.bin missing next to the exe.", -1, &fail,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            } else if (snap.notice == PW_NOTICE_STALE) {
                DrawTextW(hdc, L"Client patched. Replace keychain.bin.", -1, &fail,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            } else {
                DrawTextW(hdc, L"Capture failed. Npcap + Run as administrator.", -1, &fail,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            }
            y += 22;
        }
        if (snap.last_parts_n > 1) {
            split.left = GRIP_W + 8;
            split.top = y;
            split.right = STRIP_W - 8;
            split.bottom = y + 18;
            split2 = split;
            split2.top = y + 18;
            split2.bottom = y + 40;
            SelectObject(hdc, g_font_sm);
            SetTextColor(hdc, RGB(170, 174, 184));
            swprintf(text, 96, L"%u targets", snap.last_parts_n);
            DrawTextW(hdc, text, -1, &split, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            text[0] = 0;
            show = snap.last_parts_n < 4u ? snap.last_parts_n : 4u;
            for (i = 0; i < show; i++) {
                WCHAR piece[24];
                if (i) {
                    lstrcatW(text, L" + ");
                }
                fmt_num(piece, 24, snap.last_parts[i]);
                lstrcatW(text, piece);
            }
            if (snap.last_parts_n > 4u) {
                lstrcatW(text, L" + ...");
            }
            SetTextColor(hdc, RGB(80, 220, 140));
            DrawTextW(hdc, text, -1, &split2, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }
        {
            RECT plot, glab, head, name_r, cast_r, dmg_r, pct_r;
            int gy = STRIP_H + after_split();
            int sy;
            unsigned row;

            glab.left = GRIP_W + 8;
            glab.top = gy;
            glab.right = STRIP_W - 8;
            glab.bottom = gy + GRAPH_LABEL_H;
            SelectObject(hdc, g_font_sm);
            SetTextColor(hdc, RGB(136, 136, 144));
            DrawTextW(hdc, L"30s", -1, &glab, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            swprintf(text, 96, L"peak %llu", (unsigned long long)(snap.peak_dps + 0.5));
            DrawTextW(hdc, text, -1, &glab, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

            plot.left = GRIP_W + 8;
            plot.top = glab.bottom;
            plot.right = STRIP_W - 8;
            plot.bottom = plot.top + GRAPH_H;
            draw_dmg_graph(hdc, snap.graph, &plot);

            sy = plot.bottom + GRAPH_GAP;
            head.left = GRIP_W + 8;
            head.top = sy;
            head.right = STRIP_W - 8;
            head.bottom = sy + SKILL_HEAD_H;
            DrawTextW(hdc, L"Skill mix", -1, &head, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            for (row = 0; row < snap.skill_n && row < PW_SKILL_UI; row++) {
                int top = sy + SKILL_HEAD_H + (int)row * SKILL_LINE_H;
                unsigned pct = 0;
                WCHAR name[48];
                RECT gap_r;

                skill_label(name, 48, snap.skills[row].id);
                name_r.left = GRIP_W + 8;
                name_r.top = top;
                name_r.right = GRIP_W + 142;
                name_r.bottom = top + SKILL_LINE_H;
                cast_r = name_r;
                cast_r.left = name_r.right;
                cast_r.right = cast_r.left + 28;
                gap_r = cast_r;
                gap_r.left = cast_r.right;
                gap_r.right = gap_r.left + 52;
                dmg_r = gap_r;
                dmg_r.left = gap_r.right;
                dmg_r.right = STRIP_W - 44;
                pct_r = dmg_r;
                pct_r.left = dmg_r.right;
                pct_r.right = STRIP_W - 8;
                SetTextColor(hdc, RGB(220, 220, 224));
                DrawTextW(hdc, name, -1, &name_r,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
                swprintf(text, 96, L"%u", snap.skills[row].casts);
                SetTextColor(hdc, RGB(170, 174, 184));
                DrawTextW(hdc, text, -1, &cast_r, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
                if (snap.skills[row].avg_ms) {
                    swprintf(text, 96, L"%ums", snap.skills[row].avg_ms);
                } else {
                    lstrcpyW(text, L"-");
                }
                DrawTextW(hdc, text, -1, &gap_r, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                fmt_compact(nbuf, 32, snap.skills[row].dmg);
                SetTextColor(hdc, RGB(80, 220, 140));
                DrawTextW(hdc, nbuf, -1, &dmg_r, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
                if (snap.session_total) {
                    pct = (unsigned)((snap.skills[row].dmg * 100ull + snap.session_total / 2ull) /
                                     snap.session_total);
                }
                swprintf(text, 96, L"%u%%", pct);
                SetTextColor(hdc, RGB(170, 174, 184));
                DrawTextW(hdc, text, -1, &pct_r, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
            }
        }
        btn_lock_rect(&lockr);
        btn_reset_rect(&resetr);
        FillRect(hdc, &lockr, btnb);
        FillRect(hdc, &resetr, btnb);
        SelectObject(hdc, g_font_sm);
        SetTextColor(hdc, RGB(220, 220, 224));
        DrawTextW(hdc, g_click_through ? L"Unlock" : L"Lock", -1, &lockr,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        DrawTextW(hdc, L"Reset", -1, &resetr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    SelectObject(hdc, old);
    if (old_bitmap) {
        BitBlt(target, 0, 0, rc.right - rc.left, rc.bottom - rc.top,
               hdc, 0, 0, SRCCOPY);
        SelectObject(hdc, old_bitmap);
        DeleteObject(back);
        DeleteDC(buffer);
    }
    DeleteObject(bg);
    DeleteObject(gripb);
    DeleteObject(btnb);
    EndPaint(hwnd, &ps);
}

static void
tick(HWND hwnd)
{
    PwMeterSnap snap;
    uint64_t t = now_ms();

    pw_ingest_snap(&snap);
    if (snap.notice != g_notice || snap.last_parts_n != g_last_parts_n) {
        g_notice = snap.notice;
        g_last_parts_n = snap.last_parts_n;
        g_placed = 0;
    }
    g_game = find_game_window(find_pid());
    place_overlay(hwnd, g_game);
    if (memcmp(&snap, &g_last_snap, sizeof(snap)) != 0) {
        g_last_snap = snap;
        InvalidateRect(hwnd, NULL, FALSE);
        g_last_paint_request = t;
    } else {
        request_repaint(hwnd, t);
    }
}

static LRESULT CALLBACK
wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_ERASEBKGND:
        return 1;
    case WM_TIMER:
        tick(hwnd);
        return 0;
    case WM_PAINT:
        paint_overlay(hwnd);
        return 0;
    case WM_MOUSEACTIVATE:
        return MA_NOACTIVATE;
    case WM_NCHITTEST: {
        POINT pt;
        if (g_click_through) {
            return HTTRANSPARENT;
        }
        pt.x = (short)LOWORD(lp);
        pt.y = (short)HIWORD(lp);
        ScreenToClient(hwnd, &pt);
        if (pt.x >= 0 && pt.x < GRIP_W && pt.y >= 0 && pt.y < STRIP_H) {
            return HTCAPTION;
        }
        return HTCLIENT;
    }
    case WM_LBUTTONUP: {
        POINT pt;
        RECT lockr, resetr;
        pt.x = (short)LOWORD(lp);
        pt.y = (short)HIWORD(lp);
        if (g_expanded) {
            btn_lock_rect(&lockr);
            btn_reset_rect(&resetr);
            if (PtInRect(&lockr, pt)) {
                set_click_through(hwnd, !g_click_through);
                InvalidateRect(hwnd, NULL, FALSE);
                return 0;
            }
            if (PtInRect(&resetr, pt)) {
                pw_ingest_reset();
                InvalidateRect(hwnd, NULL, FALSE);
                return 0;
            }
        }
        if (pt.y >= 0 && pt.y < STRIP_H && pt.x >= GRIP_W) {
            g_expanded = !g_expanded;
            g_placed = 0;
            place_overlay(hwnd, g_game);
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    }
    case WM_ENTERSIZEMOVE:
        g_dragging = 1;
        return 0;
    case WM_EXITSIZEMOVE:
        g_dragging = 0;
        if (g_game) {
            save_rel_from_window(hwnd, g_game);
        }
        return 0;
    case WM_HOTKEY:
        if (wp == HOTKEY_RESET) {
            pw_ingest_reset();
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (wp == HOTKEY_CLICK) {
            set_click_through(hwnd, !g_click_through);
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        UnregisterHotKey(hwnd, HOTKEY_RESET);
        UnregisterHotKey(hwnd, HOTKEY_CLICK);
        pw_ingest_stop();
        if (g_font) {
            DeleteObject(g_font);
        }
        if (g_font_sm) {
            DeleteObject(g_font_sm);
        }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

int WINAPI
wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show)
{
    WNDCLASSEXW wc;
    MSG msg;
    DWORD ex;
    char err[96];

    (void)prev;
    (void)cmd;
    (void)show;

    g_singleton = CreateMutexW(NULL, TRUE, L"Local\\PlayCabalWire.SingleInstance");
    if (!g_singleton) {
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_singleton);
        g_singleton = NULL;
        return 0;
    }

    SetProcessDPIAware();
    pw_ingest_start(NULL, err, (int)sizeof(err));

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = OVERLAY_CLASS;
    if (!RegisterClassExW(&wc)) {
        pw_ingest_stop();
        return 1;
    }

    g_font = CreateFontW(-20, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                         0, L"Segoe UI");
    g_font_sm = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                            0, L"Segoe UI");

    ex = WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED | WS_EX_NOACTIVATE;
    g_hwnd = CreateWindowExW(ex, OVERLAY_CLASS, L"Cabal DPS", WS_POPUP, 24, 120, STRIP_W, STRIP_H,
                             NULL, NULL, inst, NULL);
    if (!g_hwnd) {
        pw_ingest_stop();
        return 1;
    }

    SetLayeredWindowAttributes(g_hwnd, 0, 230, LWA_ALPHA);
    RegisterHotKey(g_hwnd, HOTKEY_RESET, 0, VK_F9);
    RegisterHotKey(g_hwnd, HOTKEY_CLICK, 0, VK_F8);
    SetTimer(g_hwnd, 1, POLL_MS, NULL);
    tick(g_hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
