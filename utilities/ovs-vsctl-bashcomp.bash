SAVE_IFS=$IFS
IFS="
"
_OVS_VSCTL_INVOCATION_OPTS=""

# Run ovs-vsctl with any needed invocation options useful for making
# sure that ovs-vsctl is always called with the correct --db argument.
_ovs_vsctl () {
    ovs-vsctl ${_OVS_VSCTL_INVOCATION_OPTS} "$@"
}

# ovs-vsctl --commands outputs in this format:
#
# main = <localopts>,<name>,<options>
# localopts = ([<localopt>] )*
# localopt = --[^]]*
# name = [^,]*
# arguments = ((!argument|?argument|*argument|+argument) )*
# argument = ([^ ]*|argument\|argument)
#
# The [] characters in local options are just delimiters.  The
# argument prefixes mean:
#   !argument :: The argument is required
#   ?argument :: The argument is optional
#   *argument :: The argument may appear any number (0 or more) times
#   +argument :: The argument may appear one or more times
# A bar (|) character in an argument means thing before bar OR thing
# after bar; for example, del-port can take a port or an interface.

_OVS_VSCTL_COMMANDS="$(_ovs_vsctl --commands)"

# This doesn't complete on short arguments, so it filters them out.
_OVS_VSCTL_OPTIONS="$(_ovs_vsctl --options | awk '/^--/ { print $0 }' \
                      | sed -e 's/\(.*\)=ARG/\1=/')"
IFS=$SAVE_IFS

declare -A _OVS_VSCTL_PARSED_ARGS

# This is a convenience function to make sure that user input is
# looked at as a fixed string when being compared to something.  $1 is
# the input; this behaves like 'grep "^$1"' but deals with regex
# metacharacters in $1.
_ovs_vsctl_check_startswith_string () {
    awk 'index($0, thearg)==1' thearg="$1"
}

_ovs_vsctl_bashcomp_globalopt () {
    local options result
    options=""
    result=$(printf "%s\n" "${_OVS_VSCTL_OPTIONS}" \
             | _ovs_vsctl_check_startswith_string "${1%=*}")
    if [[ $result =~ "=" ]]; then
        options="NOSPACE"
    fi
    printf -- "${options}\nEO\n${result}"
}

_ovs_vsctl_bashcomp_localopt () {
    local options result possible_opts

    possible_opts=$(printf "%s\n" "${_OVS_VSCTL_COMMANDS}" | cut -f1 -d',')
    # This finds all options that could go together with the
    # already-seen ones
    for prefix_arg in $1; do
        possible_opts=$(printf "%s\n" "$possible_opts" \
                        | grep -- "\[${prefix_arg%%=*}=\?\]")
    done
    result=$(printf "%s\n" "${possible_opts}" \
             | tr ' ' '\n' | tr -s '\n' | sort | uniq)
    # This removes the already-seen options from the list so that
    # users aren't completed for the same option twice.
    for prefix_arg in $1; do
        result=$(printf "%s\n" "${result}" \
                 | grep -v -- "\[${prefix_arg%%=*}=\?\]")
    done
    result=$(printf "%s\n" "${result}" | sed -ne 's/\[\(.*\)\]/\1/p' \
             | _ovs_vsctl_check_startswith_string "$2")
    if [[ $result =~ "=" ]]; then
        options="NOSPACE"
    fi
    printf -- "${options}\nEO\n${result}"
}

_ovs_vsctl_bashcomp_command () {
    local result possible_cmds

    possible_cmds=$(printf "%s\n" "${_OVS_VSCTL_COMMANDS}")
    for prefix_arg in $1; do
        possible_cmds=$(printf "%s\n" "$possible_cmds" \
                        | grep -- "\[$prefix_arg=\?\]")
    done
    result=$(printf "%s\n" "${possible_cmds}" \
             | cut -f2 -d',' \
             | _ovs_vsctl_check_startswith_string "$2")
    printf -- "${result}"
}

_ovs_vsctl_detect_nonzero_completions () {
    local tmp newarg

    newarg=${1#*EO}
    readarray tmp <<< "$newarg"
    if [ "${#tmp[@]}" -eq 1 ] && [ "${#newarg}" -eq 0 ]; then
        return 1
    fi
    return 0
}

_ovs_vsctl_expand_command () {
    result=$(printf "%s\n" "${_OVS_VSCTL_COMMANDS}" \
             | grep -- ",$1," | cut -f3 -d',' | tr ' ' '\n' \
             | awk '/\+.*/ { name=substr($0,2);
                             print "!"name; print "*"name; next; }
                    1')
    printf -- "${result}\n!--"
}

_ovs_vsctl_complete_table () {
    local result

    result=$(ovsdb-client --no-heading list-tables \
             | _ovs_vsctl_check_startswith_string "$1")
    printf -- "EO\n%s\n" "${result}"
}

_ovs_vsctl_complete_record () {
    local table uuids names

    table="${_OVS_VSCTL_PARSED_ARGS[TABLE]}"
    # Tables should always have an _uuid column
    uuids=$(_ovs_vsctl --no-heading -f table -d bare --columns=_uuid \
                      list $table | _ovs_vsctl_check_startswith_string "$1")
    # Names don't always exist, silently ignore if the name column is
    # unavailable.
    names=$(_ovs_vsctl --no-heading -f table -d bare \
                      --columns=name list $table \
                      2>/dev/null \
            | _ovs_vsctl_check_startswith_string "$1")
    printf -- "EO\n%s\n%s\n" "${uuids}" "${names}"
}

_ovs_vsctl_complete_bridge () {
    local result

    result=$(_ovs_vsctl list-br | _ovs_vsctl_check_startswith_string "$1")
    printf -- "EO\n%s\n" "${result}"
}

_ovs_vsctl_complete_port () {
    local ports result

    if [ -n "${_OVS_VSCTL_PARSED_ARGS[BRIDGE]}" ]; then
        ports=$(_ovs_vsctl list-ports "${_OVS_VSCTL_PARSED_ARGS[BRIDGE]}")
    else
        local all_ports
        all_ports=$(_ovs_vsctl --format=table \
                              --no-headings \
                              --columns=name \
                              list Port)
        ports=$(printf "$all_ports" | sort | tr -d '" ' | uniq -u)
    fi
    result=$(_ovs_vsctl_check_startswith_string "$1" <<< "$ports")
    printf -- "EO\n%s\n" "${result}"
}

# $1:  Atom to complete (as usual)
# $2:  Table to complete the key in
# $3:  Column to find keys in
# $4:  Prefix for each completion
_ovs_vsctl_complete_key_given_table_column () {
    local keys

    keys=$(_ovs_vsctl --no-heading --columns="$3" list \
                     "$2" \
           | tr -d '{\"}' | tr -s ', ' '\n' | cut -d'=' -f1 \
           | xargs printf "$4%s\n" | _ovs_vsctl_check_startswith_string "$1")
    result="${keys}"
    printf -- "%s\n" "${result}"
}

_ovs_vsctl_complete_key () {
    # KEY is used in both br-set-external-id/br-get-external id (in
    # which case it is implicitly a key in the external-id column) and
    # in remove, where it is a table key.  This checks to see if table
    # is set (the remove scenario), and then decides what to do.
    local result

    if [ -n "${_OVS_VSCTL_PARSED_ARGS[TABLE]}" ]; then
        local column=$(tr -d '\n' <<< ${_OVS_VSCTL_PARSED_ARGS["COLUMN"]})
        result=$(_ovs_vsctl_complete_key_given_table_column \
                     "$1" \
                     ${_OVS_VSCTL_PARSED_ARGS["TABLE"]} \
                     $column \
                     "")
    else
        result=$(_ovs_vsctl br-get-external-id \
                           ${_OVS_VSCTL_PARSED_ARGS["BRIDGE"]} \
                 | cut -d'=' -f1 | _ovs_vsctl_check_startswith_string "$1")
    fi
    printf -- "EO\n%s\n" "${result}"
}

_ovs_vsctl_complete_key_value () {
    local orig_completions new_completions
    orig_completions=$(_ovs_vsctl_complete_key "$1")
    for completion in ${orig_completions#*EO}; do
        new_completions="${new_completions} ${completion}="
    done
    printf -- "NOSPACE\nEO\n%s" "${new_completions}"
}

_ovs_vsctl_complete_column () {
    local columns result

    columns=$(ovsdb-client --no-headings list-columns \
                           ${_OVS_VSCTL_PARSED_ARGS["TABLE"]})
    result=$(printf "%s\n" "${columns}" \
             | cut -d' ' -f1 \
             | _ovs_vsctl_check_startswith_string "$1" | sort | uniq)
    printf -- "EO\n%s\n" "${result}"
}

_ovs_vsctl_get_sys_intf () {
    local result
    case "$(uname -o)" in
        *Linux*)
            result=$(ip -o link 2>/dev/null | cut -d':' -f2 \
                     | sed -e 's/^ \(.*\)/\1/')
            ;;
        *)
            result=$(ifconfig -a -s 2>/dev/null | cut -f1 -d' ' | tail -n +2)
            ;;
    esac
    printf "%s\n" "${result}"
}

_ovs_vsctl_complete_sysiface () {
    local result

    result=$(_ovs_vsctl_get_sys_intf | _ovs_vsctl_check_startswith_string "$2")
    printf -- "EO\n%s\n" "${result}"
}

_ovs_vsctl_complete_iface () {
    local bridges result
    bridges=$(_ovs_vsctl list-br)
    for bridge in $bridges; do
        local ifaces
        ifaces=$(_ovs_vsctl list-ifaces "${bridge}")
        result="${result} ${ifaces}"
    done
    printf "EO\n%s\n" "${result}"
}

_ovs_vsctl_complete_column_optkey_value () {
    local result column key value completion

    column=$(printf "%s\n" "$1" | cut -d '=' -f1 | cut -d':' -f1)
    key=$(printf "%s\n" "$1" | cut -d '=' -f1 | cut -s -d':' -f2)
    #    table=$(_ovs_vsctl_get_current_table)
    # The tr -d '\n' <<< makes sure that there are no leading or
    # trailing accidental newlines.
    table=$(tr -d '\n' <<< ${_OVS_VSCTL_PARSED_ARGS["TABLE"]})
    # This might also be called after add-port or add-bond; in those
    # cases, the table should implicitly be assumed to be "Port".
    # This is done by checking if a NEW- parameter has been
    # encountered and, if it has, using that type without the NEW- as
    # the table.
    if [ -z "$table" ]; then
        if [ -n ${_OVS_VSCTL_PARSED_ARGS["NEW-PORT"]} ] \
           || [ -n ${_OVS_VSCTL_PARSED_ARGS["NEW-BOND-PORT"]} ]; then
            table="Port"
        fi
    fi

    if [ -z "$key" ]; then
        local columns=$(ovsdb-client --no-headings list-columns $table)
        result=$(printf "%s\n" "${columns}" \
                 | awk '/key.*value/ { print $1":"; next }
                                     { print $1; next }' \
                 | _ovs_vsctl_check_startswith_string "$1" | sort | uniq)
    fi
    if [[ $1 =~ ":" ]]; then
        result=$(_ovs_vsctl_complete_key_given_table_column \
                     "$key" "$table" "$column" "$column:")

    fi
    printf -- "NOSPACE\nEO\n%s\n" "${result}"
}

_ovs_vsctl_complete_filename () {
    local result

    result=$(compgen -o filenames -A file "$1")
    printf -- "EO\n%s\n" "${result}"
}

_ovs_vsctl_complete_bridge_fail_mode () {
    printf -- "EO\nstandalone\nsecure"
}

_ovs_vsctl_complete_target () {
    local result

    if [[ "$1" =~ ^p?u ]]; then
        local protocol pathname expansion_base result
        protocol=$(cut -d':' -f1 <<< "$1")
        pathname=$(cut -s -d':' -f2 <<< "$1")
        expansion_base=$(compgen -W "unix punix" "$protocol")
        expansion_base="$expansion_base:"
        result=$(compgen -o filenames -A file \
                         -P $expansion_base "${pathname}")
        printf -- "NOSPACE\nEO\n%s\n" "${result}"
    else
        printf -- "NOSPACE\nEO\nssl:\ntcp:\nunix:\npssl:\nptcp:\npunix:"
    fi
}

_ovs_vsctl_get_PS1 () {

    # Original inspiration from
    # http://stackoverflow.com/questions/10060500/bash-how-to-evaluate-ps1-ps2,
    # but changed quite a lot to make it more robust.

    # Make sure the PS1 used doesn't include any of the special
    # strings used to identify the prompt
    myPS1="$(sed 's/Begin prompt/\\Begin prompt/; s/End prompt/\\End prompt/' <<< "$PS1")"
    # Export the current environment in case the prompt uses any
    vars="$(env | cut -d'=' -f1)"
    for var in $vars; do export $var; done
    funcs="$(declare -F | cut -d' ' -f3)"
    for func in $funcs; do export -f $func; done
    # Get the prompt
    v="$(bash --norc --noprofile -i 2>&1 <<< $'PS1=\"'"$myPS1"$'\" \n# Begin prompt\n# End prompt')"
    v="${v##*# Begin prompt}"
    printf -- "$(tail -n +2 <<< "${v%# End prompt*}" | sed 's/\\Begin prompt/Begin prompt/; s/\\End prompt/End prompt/')"

}

_ovs_vsctl_complete_new () {
    local two_word_type message result

    two_word_type="${2/-/ }"
    message="\nEnter a ${two_word_type,,}:\n$(_ovs_vsctl_get_PS1)$COMP_LINE"
    if [ -n "$1" ]; then
        result="$1"
    else
        result="x"
    fi
    printf -- "NOCOMP\nBM%sEM\nEO\n%s\n" "${message}" "${result}"
}

_ovs_vsctl_complete_dashdash () {
    printf -- "EO\n%s\n" "--"
}


# These functions are given two arguments:
#
# $1 is the word being completed
#
# $2 is the type of completion --- only currently useful for the
# NEW-* functions.
#
# There are a few argument types that are not completed:
#
# - VALUE: Values are likely to be unique.
# - ARG: Can be any text
#
# Note that the NEW-* functions actually are ``completed''; currently
# the completions are just used to save the fact that they have
# appeared for later use (i.e. implicit table calculation).
#
# The output is of the form <options>EO<completions>, where EO stands
# for end options.  Currently available options are:
#  - NOSPACE: Do not add a space at the end of each completion
#  - NOCOMP: Do not complete, but store the output of the completion
#    func in _OVS_VSCTL_PARSED_ARGS for later usage.
#  - BM<message>EM: Print the <message>
declare -A _OVS_VSCTL_ARG_COMPLETION_FUNCS=(
    ["TABLE"]=_ovs_vsctl_complete_table
    ["RECORD"]=_ovs_vsctl_complete_record
    ["BRIDGE"]=_ovs_vsctl_complete_bridge
    ["PARENT"]=_ovs_vsctl_complete_bridge
    ["PORT"]=_ovs_vsctl_complete_port
    ["KEY"]=_ovs_vsctl_complete_key
    ["IFACE"]=_ovs_vsctl_complete_iface
    ["SYSIFACE"]=_ovs_vsctl_complete_sysiface
    ["COLUMN"]=_ovs_vsctl_complete_column
    ["COLUMN?:KEY"]=_ovs_vsctl_complete_column_optkey_value
    ["COLUMN?:KEY=VALUE"]=_ovs_vsctl_complete_column_optkey_value
    ["KEY=VALUE"]=_ovs_vsctl_complete_key_value
    ["?KEY=VALUE"]=_ovs_vsctl_complete_key_value
    ["PRIVATE-KEY"]=_ovs_vsctl_complete_filename
    ["CERTIFICATE"]=_ovs_vsctl_complete_filename
    ["CA-CERT"]=_ovs_vsctl_complete_filename
    ["MODE"]=_ovs_vsctl_complete_bridge_fail_mode
    ["TARGET"]=_ovs_vsctl_complete_target
    ["NEW-BRIDGE"]=_ovs_vsctl_complete_new
    ["NEW-PORT"]=_ovs_vsctl_complete_sysiface
    ["NEW-BOND-PORT"]=_ovs_vsctl_complete_new
    ["NEW-VLAN"]=_ovs_vsctl_complete_new
    ["--"]=_ovs_vsctl_complete_dashdash
)

# $1: Argument type, may include vertical bars to mean OR
# $2: Beginning of completion
#
# Note that this checks for existance in
# _OVS_VSCTL_ARG_COMPLETION_FUNCS; if the argument type ($1) is not
# there it will fail gracefully.
_ovs_vsctl_possible_completions_of_argument () {
    local possible_types completions tmp

    completions="EO"

    possible_types=$(printf "%s\n" "$1" | tr '|' '\n')
    for type in $possible_types; do
        if [ ${_OVS_VSCTL_ARG_COMPLETION_FUNCS["${type^^}"]} ]; then
            tmp=$(${_OVS_VSCTL_ARG_COMPLETION_FUNCS["${type^^}"]} \
                      "$2" "${type^^}")
            tmp_noEO="${tmp#*EO}"
            tmp_EO="${tmp%%EO*}"
            completions=$(printf "%s%s\n%s" "${tmp_EO}" \
                                 "${completions}" "${tmp_noEO}")
        fi
    done
    printf "%s\n" "${completions}"
}

# $1 = List of argument types
# $2 = current pointer into said list
# $3 = word to complete on
# Outputs list of possible completions
# The return value is the index in the cmd_args($1) list that should
# next be matched, if only one of them did, or 254 if there are no
# matches, so it doesn't know what comes next.
_ovs_vsctl_complete_argument() {
    local cmd_args arg expansion index

    new=$(printf "%s\n" "$1" | grep -- '.\+')
    readarray -t cmd_args <<< "$new";
    arg=${cmd_args[$2]}
    case ${arg:0:1} in
        !)
            expansion=$(_ovs_vsctl_possible_completions_of_argument \
                            "${arg:1}" $3)
            index=$(($2+1))
            ;;
        \?|\*)
            local tmp1 tmp2 arg2_index tmp2_noEO tmp2_EO
            tmp1=$(_ovs_vsctl_possible_completions_of_argument "${arg:1}" $3)
            tmp2=$(_ovs_vsctl_complete_argument "$1" "$(($2+1))" "$3")
            arg2_index=$?
            if _ovs_vsctl_detect_nonzero_completions "$tmp1" \
               && _ovs_vsctl_detect_nonzero_completions "$tmp2"; then
                if [ "${arg:0:1}" = "*" ]; then
                    index=$2;
                else
                    index=$(($2+1));
                fi
            fi
            if _ovs_vsctl_detect_nonzero_completions "$tmp1" \
               && (! _ovs_vsctl_detect_nonzero_completions "$tmp2"); then
                if [ "${arg:0:1}" = "*" ]; then
                    index=$2;
                else
                    index=$(($2+1));
                fi
            fi
            if (! _ovs_vsctl_detect_nonzero_completions "$tmp1") \
               && _ovs_vsctl_detect_nonzero_completions "$tmp2"; then
                index=$arg2_index
            fi
            if (! _ovs_vsctl_detect_nonzero_completions "$tmp1") \
               && (! _ovs_vsctl_detect_nonzero_completions "$tmp2"); then
                index=254
            fi
            # Don't allow secondary completions to inhibit primary
            # completions:
            if [[ $tmp2 =~ ^([^E]|E[^O])*NOCOMP ]]; then
                tmp2=""
            fi
            tmp2_noEO="${tmp2#*EO}"
            tmp2_EO="${tmp2%%EO*}"
            expansion=$(printf "%s%s\n%s" "${tmp2_EO}" \
                               "${tmp1}" "${tmp2_noEO}")
            ;;
    esac
    printf "%s\n" "$expansion"
    return $index
}

_ovs_vsctl_detect_nospace () {
    if [[ $1 =~ ^([^E]|E[^O])*NOSPACE ]]; then
        _OVS_VSCTL_COMP_NOSPACE=true
    fi
}

_ovs_vsctl_process_messages () {
    local message

    message="${1#*BM}"
    message="${message%%EM*}"
    if [ "$test" = "true" ]; then
        printf -- "--- BEGIN MESSAGE"
    fi
    printf "${message}"
    if [ "$test" = "true" ]; then
        printf -- "--- END MESSAGE"
    fi
}

# The general strategy here is that the same functions that decide
# completions can also capture the necessary context for later
# completions.  This means that there is no distinction between the
# processing for words that are not the current word and words that
# are the current word.
#
# Parsing up until the command word happens starts with everything
# valid; as the syntax order of ovs-vsctl is fairly strict, when types
# of words that preclude other words from happending can turn them
# off; this is controlled by valid_globals, valid_opts, and
# valid_commands.  given_opts is used to narrow down which commands
# are valid based on the previously given options.
#
# After the command has been detected, the parsing becomes more
# complicated.  The cmd_pos variable is set to 0 when the command is
# detected; it is used as a pointer into an array of the argument
# types for that given command.  The argument types are stored in both
# cmd_args and raw_cmd as the main loop uses properties of arrays to
# detect certain conditions, but arrays cannot be passed to functions.
# To be able to deal with optional or repeatable arguments, the exit
# status of the function _ovs_vsctl_complete_argument represents where
# it has determined that the next argument will be.
_ovs_vsctl_bashcomp () {
    local cur valid_globals cmd_args raw_cmd cmd_pos valid_globals valid_opts
    local test="false"
    if [ "$1" = "test" ]; then
        test="true"
        export COMP_LINE="ovs-vsctl $2"
        tmp="ovs-vsctl"$'\n'"$(tr ' ' '\n' <<< "${COMP_LINE}x")"
        tmp="${tmp%x}"
        readarray -t COMP_WORDS \
                  <<< "$tmp"
        export COMP_WORDS
        export COMP_CWORD="$((${#COMP_WORDS[@]}-1))"
        export PS1="> "
        # This is used to make the PS1-extraction code not emit extra
        # escape sequences; it seems like bash assumes that unknown
        # terminal names are dumb which means this should work even in
        # the unlikely occurence of the terminal "dumb" not existing.
        export TERM="dumb"
    fi

    db=$(sed -n 's/.*--db=\([^ ]*\).*/\1/p' <<< "$COMP_LINE")
    if [ -n "$db" ]; then
        _OVS_VSCTL_INVOCATION_OPTS="--db=$db"
    fi

    if ! _ovs_vsctl get-manager 2>/dev/null; then
        _OVS_VSCTL_INVOCATION_OPTS=""
        if ! _ovs_vsctl get-manager 2>/dev/null; then
            return 1;
        fi
    fi

    _OVS_VSCTL_PARSED_ARGS=()
    cmd_pos=-1
    cur=${COMP_WORDS[COMP_CWORD]}
    valid_globals=true
    valid_opts=true
    valid_commands=true
    given_opts=""
    index=1
    export COMP_WORDBREAKS=" "
    for word in "${COMP_WORDS[@]:1:${COMP_CWORD}} "; do
        _OVS_VSCTL_COMP_NOSPACE=false
        local completion
        completion=""
        if [ $cmd_pos -gt -1 ]; then
            local tmp tmp_nospace arg possible_newindex
            tmp=$(_ovs_vsctl_complete_argument "$raw_cmd" "$cmd_pos" "$word")
            possible_newindex=$?
            # Check for nospace
            _ovs_vsctl_detect_nospace $tmp
            # Remove all options
            tmp_nospace="${tmp#*EO}"
            #tmp_nospace=$(sed -e 's/^\([^E]\|E[^O]\)*EO//' <<< "$tmp")
            # Allow commands to specify that they should not be
            # completed
            if ! [[ $tmp =~ ^([^E]|E[^O])*NOCOMP ]]; then
                completion="${completion} ${tmp_nospace}"
            else
                # Only allow messages when there is no completion
                # printout and when on the current word.
                if [ $index -eq $COMP_CWORD ]; then
                    _ovs_vsctl_process_messages "${tmp}"
                fi
            fi
            if [[ $cmd_pos -lt ${#cmd_args} ]]; then
                _OVS_VSCTL_PARSED_ARGS["${cmd_args[$cmd_pos]:1}"]=$word
            fi
            if [ $possible_newindex -lt 254 ]; then
                cmd_pos=$possible_newindex
            fi
        fi

        if [ $valid_globals == true ]; then
            tmp=$(_ovs_vsctl_bashcomp_globalopt $word)
            _ovs_vsctl_detect_nospace $tmp
            completion="${completion} ${tmp#*EO}"
        fi
        if [ $valid_opts == true ]; then
            tmp=$(_ovs_vsctl_bashcomp_localopt "$given_opts" $word)
            _ovs_vsctl_detect_nospace $tmp
            completion="${completion} ${tmp#*EO}"
            if [ $index -lt $COMP_CWORD ] \
               && _ovs_vsctl_detect_nonzero_completions "$tmp"; then
                valid_globals=false
                given_opts="${given_opts} ${word}"
            fi
        fi
        if [ $valid_commands = true ]; then
            tmp=$(_ovs_vsctl_bashcomp_command "$given_opts" $word)
            _ovs_vsctl_detect_nospace $tmp
            completion="${completion} ${tmp#*EO}"
            if [ $index -lt $COMP_CWORD ] \
               && _ovs_vsctl_detect_nonzero_completions "$tmp"; then
                valid_globals=false
                valid_opts=false
                valid_commands=false
                cmd_pos=0
                raw_cmd=$(_ovs_vsctl_expand_command "$word")
                readarray -t cmd_args <<< "$raw_cmd"
            fi
        fi
        if [ "$word" = "--" ] && [ $index -lt $COMP_CWORD ]; then
            _OVS_VSCTL_PARSED_AGS=()
            cmd_pos=-1
            valid_globals=true
            valid_opts=true
            valid_commands=true
            given_opts=""
        fi
        completion="$(sort <<< "$(tr ' ' '\n' <<< ${completion})")"
        if [ $index -eq $COMP_CWORD ]; then
            if [ "$test" = "true" ]; then
                if [ "${_OVS_VSCTL_COMP_NOSPACE}" = "true" ]; then
                    for comp in $completion; do
                        printf "%s\n" "$comp"
                    done
                else
                    for comp in $completion; do
                        printf "%s \n" "$comp"
                    done
                fi
            else
                if [ "${_OVS_VSCTL_COMP_NOSPACE}" = "true" ]; then
                    compopt -o nospace
                    COMPREPLY=( $(compgen -W "${completion}" -- $word) )
                else
                    compopt +o nospace
                    COMPREPLY=( $(compgen -W "${completion}" -- $word) )
                fi
            fi
        fi
        #COMPREPLY=( $(compgen -W "${completion}" -- $word) )
        index=$(($index+1))
    done
}

if [ "$1" = "test" ]; then
    _ovs_vsctl_bashcomp "$@"
else
    complete -F _ovs_vsctl_bashcomp ovs-vsctl
fi
