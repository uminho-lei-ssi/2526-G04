import getpass
from controller import ClientController

# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def clear():
    print("\033[2J\033[H", end="")


def header(title: str):
    print(f"\n{'─' * 30}")
    print(f"  {title}")
    print(f"{'─' * 30}")


def prompt_choice(options: list[str]) -> int:
    for i, opt in enumerate(options, 1):
        print(f"  [{i}] {opt}")
    print()
    while True:
        raw = input("Opção: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print(f"  Escolhe um número entre 1 e {len(options)}.")


def prompt_input(label: str, hidden: bool = False) -> str:
    if hidden:
        return getpass.getpass(f"  {label}: ")
    return input(f"  {label}: ").strip()


# ---------------------------------------------------------------------------
# Menus
# ---------------------------------------------------------------------------

def start(controller: ClientController):
    """
    Ponto de entrada da interface que gere o estado global da navegação.
    """
    while True:
        # Fase 1: Menu Inicial (Login/Registo)
        authenticated = menu_login(controller)
        
        if not authenticated:
            # Se o utilizador escolheu 'Sair' no menu inicial
            break

        # Fase 2: Menu Principal (Após login)
        go_to_login = menu_principal(controller)
        
        if not go_to_login:
            # Se o utilizador escolheu 'Sair (Manter Sessão)'
            break
        
        # Se go_to_login for True, o loop recomeça e mostra o menu_inicial novamente

def menu_login(controller: ClientController):
    auth = False
    while not auth:
        clear()
        header("Secure Chat")
        choice = prompt_choice(["Login", "Registar", "Sair"])

        if choice == 2:
            return False
        elif choice == 0:
            auth = _fazer_login(controller)
        elif choice == 1:
            auth = _fazer_registo(controller)

    return auth



def _fazer_login(controller: ClientController) -> bool:
    header("Login")
    username = prompt_input("Utilizador")
    password = prompt_input("Password", hidden=True)

    ok, msg = controller.login(username, password)
    print(f"\n  {msg}")
    input("\n  Enter para continuar...")
    return ok


def _fazer_registo(controller: ClientController) -> bool:
    header("Registar")
    username = prompt_input("Utilizador")
    password = prompt_input("Password", hidden=True)
    password2 = prompt_input("Confirmar password", hidden=True)

    if password != password2:
        print("\n  As passwords não coincidem.")
        input("\n  Enter para continuar...")
        return False

    ok, msg = controller.register(username, password)
    print(f"\n  {msg}")
    input("\n  Enter para continuar...")
    return False


def menu_principal(controller: Client) -> bool:
    """Returns True to go back to login, False to quit."""
    while True:
        clear()
        header("Menu Principal")
        choice = prompt_choice(["Contactos", "Logout", "Sair (Manter Sessão)"])

        if choice == 0:
            menu_contactos(controller)
        elif choice == 1:
            _, msg = controller.logout()
            print(f"\n  {msg}")
            input("  Enter para continuar...")
            return True
        elif choice == 2:
            return False


def menu_contactos(controller: Client):
    contacts = sorted(controller.get_contacts(), key=str.lower)

    while True:
        clear()
        header("Contactos")
        options = contacts + ["<- Voltar"]
        choice = prompt_choice(options)

        if choice == len(contacts):
            return

        _abrir_conversa(contacts[choice])


def _abrir_conversa(contact: str):
    clear()
    header(f"Conversa com {contact}")
    print("  (conversa ainda não implementada)")
    input("\n  Enter para voltar...")