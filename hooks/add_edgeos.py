
def add_edgeos_to_node(node):
    if 'edgeos' not in node.OS_FAMILY_LINUX:
        node.OS_FAMILY_LINUX += ('edgeos', )
        node.OS_FAMILY_UNIX += ('edgeos', )
        node.OS_KNOWN += ('edgeos', )


def node_apply_start(repo, node, interactive=False, **kwargs):
    add_edgeos_to_node(node)


def node_run_start(repo, node, command, **kwargs):
    add_edgeos_to_node(node)


def lock_add(repo, node, lock_id, items, expiry, comment, **kwargs):
    add_edgeos_to_node(node)
