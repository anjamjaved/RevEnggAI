// Source-owned GUI for real selected-window capture acceptance. No user data.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

static bool changed = false;
static std::string mode;
static DWORD mainThread;

static void paint(HWND window, HDC dc) {
  RECT area{};
  GetClientRect(window, &area);
  if (mode == "noise") {
    const int width = area.right, height = area.bottom;
    std::vector<DWORD> pixels(static_cast<size_t>(width) * height);
    DWORD state = 42;
    for (auto& pixel : pixels) {
      state ^= state << 13; state ^= state >> 17; state ^= state << 5;
      pixel = state | 0xff000000;
    }
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = width; info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32;
    SetDIBitsToDevice(dc, 0, 0, width, height, 0, 0, 0, height,
                      pixels.data(), &info, DIB_RGB_COLORS);
    return;
  }
  const auto brush = CreateSolidBrush(changed ? RGB(80, 180, 40) : RGB(40, 120, 200));
  FillRect(dc, &area, brush); DeleteObject(brush);
  SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(255, 255, 255));
  const wchar_t text[] = L"REA source-owned window: 42";
  TextOutW(dc, 16, 16, text, sizeof(text) / sizeof(wchar_t) - 1);
}

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  if (message == WM_GETMINMAXINFO) {
    auto* bounds = reinterpret_cast<MINMAXINFO*>(lparam);
    bounds->ptMaxTrackSize = {8192, 8192};
    return 0;
  }
  if (message == WM_PAINT) {
    PAINTSTRUCT observation{};
    const auto dc = BeginPaint(window, &observation);
    paint(window, dc); EndPaint(window, &observation);
    return 0;
  }
  if (message == WM_PRINT || message == WM_PRINTCLIENT) {
    paint(window, reinterpret_cast<HDC>(wparam));
    GdiFlush();
    return 0;
  }
  if (message == WM_APP + 1) {
    changed = true;
    InvalidateRect(window, nullptr, FALSE); UpdateWindow(window);
    std::puts("{\"event\":\"changed\"}"); std::fflush(stdout);
    return 0;
  }
  if (message == WM_APP + 2) {
    std::puts("{\"event\":\"blocking\"}"); std::fflush(stdout);
    Sleep(12000);
    return 0;
  }
  if (message == WM_CLOSE) { DestroyWindow(window); return 0; }
  if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
  return IsWindowUnicode(window) ? DefWindowProcW(window, message, wparam, lparam)
                                 : DefWindowProcA(window, message, wparam, lparam);
}

int main(int count, char** arguments) {
  mode = count > 1 ? arguments[1] : "normal";
  SetProcessDPIAware();
  mainThread = GetCurrentThreadId();
  const auto instance = GetModuleHandleW(nullptr);
  const bool ansi = mode == "ansi";
  WNDCLASSW wide{}; wide.lpfnWndProc = procedure;
  wide.hInstance = instance; wide.lpszClassName = L"ReaWindowCaptureFixture";
  WNDCLASSA narrow{}; narrow.lpfnWndProc = procedure;
  narrow.hInstance = instance; narrow.lpszClassName = "ReaWindowCaptureFixture";
  if (!(ansi ? RegisterClassA(&narrow) : RegisterClassW(&wide))) return 2;
  RECT bounds{0, 0, mode == "noise" ? 1600 : 640, mode == "noise" ? 1600 : 360};
  if (mode == "large") bounds = {0, 0, 2500, 2000};
  AdjustWindowRect(&bounds, WS_OVERLAPPEDWINDOW, FALSE);
  const wchar_t* title = L"REA window fixture \u4e2d\u6587";
  char ansiTitle[128]{};
  if (!WideCharToMultiByte(CP_ACP, 0, title, -1, ansiTitle, sizeof(ansiTitle), nullptr, nullptr)) return 3;
  HWND window = ansi
    ? CreateWindowA(narrow.lpszClassName, ansiTitle, WS_OVERLAPPEDWINDOW,
        100, 100, bounds.right - bounds.left, bounds.bottom - bounds.top,
        nullptr, nullptr, instance, nullptr)
    : CreateWindowW(wide.lpszClassName, title, WS_OVERLAPPEDWINDOW,
        100, 100, bounds.right - bounds.left, bounds.bottom - bounds.top,
        nullptr, nullptr, instance, nullptr);
  if (!window) return 4;
  ShowWindow(window, SW_SHOWNOACTIVATE); UpdateWindow(window);
  RECT client{}; GetClientRect(window, &client);
  wchar_t observedTitle[128]{};
  const int titleCount = GetWindowTextW(window, observedTitle, 128);
  std::printf("{\"pid\":%lu,\"window_handle\":\"0x%llx\",\"width\":%ld,\"height\":%ld,"
              "\"title_length_estimate\":%d,\"title_copied\":%d}\n", GetCurrentProcessId(),
              static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(window)),
              client.right, client.bottom, GetWindowTextLengthW(window), titleCount);
  std::fflush(stdout);
  std::thread([window] {
    std::string command;
    while (std::getline(std::cin, command)) {
      if (command == "change") PostMessageW(window, WM_APP + 1, 0, 0);
      else if (command == "block") PostMessageW(window, WM_APP + 2, 0, 0);
      else if (command == "quit") break;
    }
    PostMessageW(window, WM_CLOSE, 0, 0);
    // Also settle if the selected window was already destroyed.
    PostThreadMessageW(mainThread, WM_QUIT, 0, 0);
  }).detach();
  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    TranslateMessage(&message); DispatchMessageW(&message);
  }
  if (IsWindow(window)) DestroyWindow(window);
  return 0;
}
