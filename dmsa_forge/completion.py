"""Shell completion script generation."""

from .cli_metadata import (
    ACTION_CHOICES,
    ACTION_SUMMARY,
    PLAN_COMPLETION_OPTIONS,
    ROOT_COMPLETION_OPTIONS,
    UPDATE_COMPLETION_OPTIONS,
    UTILITY_COMMANDS,
    completion_options_by_action,
)


def _join_tokens(tokens):
    return ' '.join(tokens)


def _zsh_words(tokens):
    return ' '.join('"%s"' % token for token in tokens)


def _completion_data():
    options_by_action = completion_options_by_action()
    return {
        'commands': _join_tokens(ACTION_CHOICES + UTILITY_COMMANDS),
        'action_names': _join_tokens(ACTION_CHOICES),
        'root_options': _join_tokens(ROOT_COMPLETION_OPTIONS),
        'plan_options': _join_tokens(PLAN_COMPLETION_OPTIONS),
        'update_options': _join_tokens(UPDATE_COMPLETION_OPTIONS),
        'assess_options': _join_tokens(options_by_action['assess']),
        'add_options': _join_tokens(options_by_action['add']),
        'verify_options': _join_tokens(options_by_action['verify']),
        'delete_options': _join_tokens(options_by_action['delete']),
        'zsh_commands': (
            ' '.join('"%s:%s"' % (command, ACTION_SUMMARY.get(command, command)) for command in ACTION_CHOICES)
            + ' "plan:dry-run shorthand" "update:update current environment"'
        ),
        'zsh_action_names': _zsh_words(ACTION_CHOICES),
        'zsh_root_options': _zsh_words(ROOT_COMPLETION_OPTIONS),
        'zsh_plan_options': _zsh_words(PLAN_COMPLETION_OPTIONS),
        'zsh_update_options': _zsh_words(UPDATE_COMPLETION_OPTIONS),
        'zsh_assess_options': _zsh_words(options_by_action['assess']),
        'zsh_add_options': _zsh_words(options_by_action['add']),
        'zsh_verify_options': _zsh_words(options_by_action['verify']),
        'zsh_delete_options': _zsh_words(options_by_action['delete']),
    }


def bash_completion_script():
    data = _completion_data()
    return '''# dmsaforge bash completion
_dmsaforge_completion() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local command="${COMP_WORDS[1]}"
  local plan_action="${COMP_WORDS[2]}"
  local root_opts="%(root_options)s"
  local plan_opts="%(plan_options)s"
  local assess_opts="%(assess_options)s"
  local add_opts="%(add_options)s"
  local verify_opts="%(verify_options)s"
  local delete_opts="%(delete_options)s"
  local update_opts="%(update_options)s"
  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "%(commands)s $root_opts" -- "$cur") )
    return 0
  fi
  if [[ "$command" == "plan" && ${COMP_CWORD} -eq 2 ]]; then
    if [[ "$cur" == -* ]]; then
      COMPREPLY=( $(compgen -W "$plan_opts" -- "$cur") )
    else
      COMPREPLY=( $(compgen -W "%(action_names)s" -- "$cur") )
    fi
    return 0
  fi
  case "$cur" in
    -*|"")
      local option_source="$root_opts"
      case "$command" in
        assess) option_source="$assess_opts" ;;
        add) option_source="$add_opts" ;;
        verify) option_source="$verify_opts" ;;
        delete) option_source="$delete_opts" ;;
        update) option_source="$update_opts" ;;
        plan)
          option_source="$plan_opts"
          case "$plan_action" in
            assess) option_source="$assess_opts" ;;
            add) option_source="$add_opts" ;;
            verify) option_source="$verify_opts" ;;
            delete) option_source="$delete_opts" ;;
          esac
          ;;
      esac
      COMPREPLY=( $(compgen -W "$option_source" -- "$cur") )
      return 0
      ;;
  esac
}
complete -F _dmsaforge_completion dmsaforge
''' % data


def zsh_completion_script():
    data = _completion_data()
    return '''# dmsaforge zsh completion
# No-persistence use for the current shell:
#   eval "$(dmsaforge --completion-script zsh)"
# For persistent use, save this output as a file on your fpath.
_dmsaforge() {
  local -a commands root_opts plan_opts assess_opts add_opts verify_opts delete_opts update_opts action_names
  commands=(%(zsh_commands)s)
  root_opts=(%(zsh_root_options)s)
  plan_opts=(%(zsh_plan_options)s)
  assess_opts=(%(zsh_assess_options)s)
  add_opts=(%(zsh_add_options)s)
  verify_opts=(%(zsh_verify_options)s)
  delete_opts=(%(zsh_delete_options)s)
  update_opts=(%(zsh_update_options)s)
  action_names=(%(zsh_action_names)s)
  if (( CURRENT == 2 )); then
    _describe 'command' commands
    _describe 'option' root_opts
    return
  fi
  if [[ "${words[2]}" == "plan" && CURRENT == 3 ]]; then
    _describe 'action' action_names
    _describe 'option' plan_opts
    return
  fi
  case "${words[2]}" in
    assess) _describe 'option' assess_opts ;;
    add) _describe 'option' add_opts ;;
    verify) _describe 'option' verify_opts ;;
    delete) _describe 'option' delete_opts ;;
    update) _describe 'option' update_opts ;;
    plan)
      case "${words[3]}" in
        assess) _describe 'option' assess_opts ;;
        add) _describe 'option' add_opts ;;
        verify) _describe 'option' verify_opts ;;
        delete) _describe 'option' delete_opts ;;
        *) _describe 'option' plan_opts ;;
      esac
      ;;
    *) _describe 'option' root_opts ;;
  esac
}
compdef _dmsaforge dmsaforge
''' % data


def completion_script(shell):
    if shell == 'bash':
        return bash_completion_script()
    return zsh_completion_script()
