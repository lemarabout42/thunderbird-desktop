/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "RecoveryUI.h"
#include "VaultSupport.h"

#include <array>

namespace thunderbird::vault {
namespace {
constexpr int kCode = 101;
struct DialogState {
  bool display = false;
  bool confirmation = false;
  std::array<wchar_t, 65> code{};
  ~DialogState() { SecureZeroMemory(code.data(), sizeof(code)); }
};

HWND Control(HWND dialog, const wchar_t* type, const wchar_t* text, DWORD style,
             int x, int y, int width, int height, int id = 0,
             DWORD extended = 0) {
  RECT bounds{x, y, x + width, y + height};
  MapDialogRect(dialog, &bounds);
  const HWND control = CreateWindowExW(
      extended, type, text, WS_CHILD | WS_VISIBLE | style, bounds.left,
      bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
      dialog, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr,
      nullptr);
  SendMessageW(control, WM_SETFONT,
               reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),
               TRUE);
  return control;
}

INT_PTR CALLBACK RecoveryProc(HWND window, UINT message, WPARAM wParam,
                              LPARAM lParam) {
  auto state =
      reinterpret_cast<DialogState*>(GetWindowLongPtrW(window, DWLP_USER));
  if (message == WM_INITDIALOG) {
    state = reinterpret_cast<DialogState*>(lParam);
    SetWindowLongPtrW(window, DWLP_USER, reinterpret_cast<LONG_PTR>(state));
    SetWindowTextW(window, state->display ? L"Conserver la clé de récupération"
                                          : L"Vérifier la clé de récupération");
    const wchar_t* instruction =
        state->display ? L"Conservez ces 64 caractères sur papier ou dans un "
                         L"lieu sûr hors de ce PC. "
                         L"Cette clé ouvre le coffre sans Windows Hello. Ne "
                         L"gardez pas de copie en clair "
                         L"ni de capture d'écran sur ce PC. "
                         L"Elle sera demandée "
                         L"à l'étape suivante pour vérifier votre copie."
        : state->confirmation
            ? L"Saisissez les 64 caractères de la clé que vous venez de "
              L"conserver. "
              L"Cela vérifie votre copie avant de créer le profil."
            : L"Saisissez les 64 caractères de votre clé de récupération. "
              L"Le coffre sera vérifié avant toute modification de sa "
              L"protection Windows Hello.";
    Control(window, L"STATIC", instruction, 0, 12, 12, 306, 50);
    const HWND edit = Control(window, L"EDIT", state->code.data(),
                              WS_TABSTOP | ES_AUTOHSCROLL |
                                  (state->display ? ES_READONLY : ES_PASSWORD),
                              12, 66, 306, 20, kCode, WS_EX_CLIENTEDGE);
    SendMessageW(edit, EM_SETLIMITTEXT, 64, 0);
    Control(window, L"BUTTON",
            state->display ? L"J'ai conservé la clé" : L"Vérifier",
            WS_TABSTOP | BS_DEFPUSHBUTTON, 126, 98, 110, 22, IDOK);
    Control(window, L"BUTTON", L"Annuler", WS_TABSTOP, 244, 98, 74, 22,
            IDCANCEL);
    SetFocus(edit);
    return FALSE;
  }
  if (message == WM_CLOSE ||
      (message == WM_COMMAND && LOWORD(wParam) == IDCANCEL)) {
    SetDlgItemTextW(window, kCode, L"");
    EndDialog(window, IDCANCEL);
    return TRUE;
  }
  if (message == WM_COMMAND && LOWORD(wParam) == IDOK && state) {
    if (!state->display &&
        GetDlgItemTextW(window, kCode, state->code.data(),
                        static_cast<int>(state->code.size())) != 64) {
      MessageBoxW(
          window,
          L"La clé doit contenir exactement 64 caractères hexadécimaux.",
          L"Clé incomplète", MB_OK | MB_ICONINFORMATION);
      return TRUE;
    }
    SetDlgItemTextW(window, kCode, L"");
    EndDialog(window, IDOK);
    return TRUE;
  }
  return FALSE;
}

bool Show(DialogState& state) {
  struct alignas(DWORD) Template {
    DLGTEMPLATE dialog;
    WORD menu;
    WORD windowClass;
    WORD title;
  } value{};
  value.dialog.style =
      WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER;
  value.dialog.cx = 330;
  value.dialog.cy = 132;
  const INT_PTR result =
      DialogBoxIndirectParamW(GetModuleHandleW(nullptr), &value.dialog, nullptr,
                              RecoveryProc, reinterpret_cast<LPARAM>(&state));
  return result == IDOK;
}

bool Parse(DialogState& state, SecretKey& secret) {
  std::string code;
  code.reserve(64);
  for (size_t i = 0; i < 64; ++i) {
    wchar_t c = state.code[i];
    if (c >= L'A' && c <= L'F') c += L'a' - L'A';
    if (c > 127) {
      SecureZeroMemory(code.data(), code.size());
      return false;
    }
    code += static_cast<char>(c);
  }
  std::array<BYTE, 32> raw{};
  const bool valid = ParseHex(code, raw.data(), raw.size()) &&
                     secret.Import(raw.data(), raw.size());
  SecureZeroMemory(raw.data(), raw.size());
  SecureZeroMemory(code.data(), code.size());
  return valid;
}
}  // namespace

bool ConfirmRecoveryCode(const SecretKey& secret) {
  if (!secret.IsValid()) return false;
  DialogState display;
  display.display = true;
  auto code = Hex(secret.Bytes().data(), secret.Bytes().size());
  for (size_t i = 0; i < code.size(); ++i)
    display.code[i] = static_cast<wchar_t>(code[i]);
  SecureZeroMemory(code.data(), code.size());
  if (!Show(display)) return false;
  for (;;) {
    DialogState confirmation;
    confirmation.confirmation = true;
    if (!Show(confirmation)) return false;
    SecretKey checked;
    if (Parse(confirmation, checked) && checked.Bytes() == secret.Bytes())
      return true;
    MessageBoxW(nullptr,
                L"La clé saisie ne correspond pas. Vérifiez votre copie.",
                L"Clé de récupération", MB_OK | MB_ICONWARNING);
  }
}

bool EnterRecoveryCode(SecretKey& secret) {
  secret.Clear();
  DialogState input;
  return Show(input) && Parse(input, secret);
}
}  // namespace thunderbird::vault
