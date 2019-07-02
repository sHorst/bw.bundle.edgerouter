

def node_apply_start(repo, node, interactive=False, **kwargs):
    node.OS_FAMILY_LINUX += ('edgeos', )
    node.OS_FAMILY_UNIX += ('edgeos', )
    node.OS_KNOWN += ('edgeos', )
