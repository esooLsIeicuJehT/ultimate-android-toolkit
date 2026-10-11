"""Small-phone-friendly menu. Each action uses the same tested CLI handlers."""
import shlex


def menu():
    from .cli import main
    actions = {
        "1": ("Inspect APK", ["apk", "inspect"], ["APK path"]),
        "2": ("Decode APK", ["apk", "decode"], ["APK path", "--out|New decoded directory"]),
        "3": ("Decompile to Java", ["apk", "decompile"], ["APK path", "--out|New Java directory"]),
        "4": ("Build unsigned APK", ["apk", "build"], ["Decoded directory", "--out|New unsigned APK path"]),
        "5": ("Create signing key", ["key", "create"], ["--out|New keystore path"]),
        "6": ("Sign APK", ["apk", "sign"], ["APK path", "--out|New signed APK path", "--keystore|Keystore path"]),
        "7": ("Verify APK", ["apk", "verify"], ["APK path"]),
        "8": ("Search files", ["search"], ["File or directory", "--query|Text to find"]),
        "9": ("Preview patch recipe", ["patch", "plan"], ["Recipe JSON path", "--root|Input directory"]),
        "10": ("Apply patch recipe", ["patch", "apply"], ["Recipe JSON path", "--root|Input directory", "--out|New output directory"]),
        "11": ("Check tools", ["doctor"], []),
    }
    while True:
        print("\nUltimate Android Toolkit")
        for key, (title, _, _) in actions.items():
            print(f"{key:>2}. {title}")
        print(" c. Run a CLI command\n q. Exit")
        try:
            choice = input("> ").strip().lower()
            if choice == "q":
                return
            if choice == "c":
                argv = shlex.split(input("uat "))
                if argv and argv[0] == "uat":
                    argv = argv[1:]
                if argv and argv[0] != "menu":
                    main(argv)
                continue
            if choice not in actions:
                continue
            _, base, prompts = actions[choice]
            argv = list(base)
            for prompt in prompts:
                if "|" in prompt:
                    flag, label = prompt.split("|", 1)
                    argv += [flag, input(label + ": ").strip()]
                else:
                    argv.append(input(prompt + ": ").strip())
            main(argv)
        except EOFError:
            return
        except (KeyboardInterrupt, ValueError):
            print("\nReturning to menu.")
