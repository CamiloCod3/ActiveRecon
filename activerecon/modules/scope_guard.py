from ..policies.scope_policy import ScopePolicy


def is_target_in_scope(target, scope_file):
    return ScopePolicy.from_file(scope_file).allows(target)
