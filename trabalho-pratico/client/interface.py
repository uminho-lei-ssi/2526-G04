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


def menu_principal(controller: ClientController) -> bool:
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


def menu_contactos(controller: ClientController):
    while True:
        clear()
        header("Contactos")
        contacts = sorted(controller.get_contacts(), key=str.lower)

        if contacts:
            for contact in contacts:
                print(f"  - {contact}")
        else:
            print("  (sem contactos)")

        print()
        options = [f"Abrir conversa: {name}" for name in contacts]
        options += ["Adicionar contacto", "Remover contacto", "<- Voltar"]
        choice = prompt_choice(options)

        if choice < len(contacts):
            _abrir_conversa(controller, contacts[choice])
            continue

        base_index = len(contacts)
        if choice == base_index:
            _adicionar_contacto(controller)
            continue

        if choice == base_index + 1:
            _remover_contacto(controller, contacts)
            continue

        if choice == base_index + 2:
            return


def _adicionar_contacto(controller: ClientController):
    clear()
    header("Adicionar contacto")
    contact = prompt_input("Nome do contacto")
    if not contact:
        print("\n  Nome de contacto invalido.")
        input("\n  Enter para continuar...")
        return

    _, msg = controller.add_contact(contact)
    print(f"\n  {msg}")
    input("\n  Enter para continuar...")


def _remover_contacto(controller: ClientController, contacts: list[str]):
    clear()
    header("Remover contacto")
    if not contacts:
        print("  Nao existem contactos para remover.")
        input("\n  Enter para continuar...")
        return

    choice = prompt_choice(contacts + ["Cancelar"])
    if choice == len(contacts):
        return

    _, msg = controller.remove_contact(contacts[choice])
    print(f"\n  {msg}")
    input("\n  Enter para continuar...")


def _abrir_conversa(controller: ClientController, contact: str):
    while True:
        clear()
        header(f"Conversa com {contact}")
        print("  /voltar para regressar")
        print()

        messages = controller.fetch_messages(contact)
        if messages:
            print("  Novas mensagens:")
            for item in messages:
                sender = item.get("from", "?")
                content = item.get("content", "")
                print(f"    {sender}: {content}")
        else:
            print("  (sem novas mensagens)")

        text = input("\n  Mensagem: ").strip()
        if text.lower() == "/voltar":
            return
        if not text:
            continue

        ok, msg = controller.send_message(contact, text)
        if not ok:
            print(f"\n  {msg}")
            input("\n  Enter para continuar...")