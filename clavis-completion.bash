_clavis() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="get env ls show attach files add edit help"

    # Complete commands as first arg
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return
    fi

    local cmd="${COMP_WORDS[1]}"

    # Commands that take a path or group
    case "$cmd" in
        get|env|ls|show|attach|add)
            # Complete --user and --url flags for add command
            if [ "$cmd" = "add" ] && [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--user --url" -- "$cur"))
                return
            fi

            # After --user or --url, no path completion (expect a value)
            if [ "$cmd" = "add" ] && { [ "$prev" = "--user" ] || [ "$prev" = "--url" ]; }; then
                return
            fi

            # Need CLAVIS_PASSWORD and db to query
            local script_dir db cli
            script_dir="$(cd "$(dirname "$(readlink -f "$(command -v clavis)")")" && pwd)"
            db="$script_dir/secrets.kdbx"
            cli="keepassxc-cli"

            [ -f "$db" ] || return
            [ -n "${CLAVIS_PASSWORD:-}" ] || return

            # Determine parent group to list
            local group="/"
            if [[ "$cur" == */* ]]; then
                group="/${cur%/*}"
            fi

            local items
            items=$(echo "$CLAVIS_PASSWORD" | "$cli" ls -q "$db" "$group" 2>/dev/null) || return

            # Build full paths for completion
            local prefix=""
            if [[ "$cur" == */* ]]; then
                prefix="${cur%/*}/"
            fi

            local candidates=()
            while IFS= read -r item; do
                [ -z "$item" ] && continue
                candidates+=("${prefix}${item}")
            done <<< "$items"

            COMPREPLY=($(compgen -W "${candidates[*]}" -- "$cur"))

            # If completing a group (ends with /), don't add a space
            if [ ${#COMPREPLY[@]} -eq 1 ] && [[ "${COMPREPLY[0]}" == */ ]]; then
                compopt -o nospace
            fi
            ;;
        files)
            # Second arg is group, third is directory
            if [ "$COMP_CWORD" -eq 3 ]; then
                compopt -o dirnames
                COMPREPLY=($(compgen -d -- "$cur"))
            else
                # Same as group completion above
                _clavis
            fi
            ;;
    esac
}

complete -F _clavis clavis
