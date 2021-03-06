---
description: The resource member command description and usage
keywords:
- resource, member
menu:
  main:
    parent: smn_cli
title: resource member
---

# hbm resource member
***

```markdown
Manage resource membership to collection

Usage:
  hbm resource member [collection] [name] [flags]

Flags:
  -a, --add      Add resource to collection
  -r, --remove   Remove resource from collection
```

## Examples

### Add a resource to a collection
```bash
# hbm collection ls
NAME                TYPE                VALUE               OPTION              COLLECTIONS
resource1           action              info
# hbm resource member --add collection1 resource1
# hbm collection ls
NAME                TYPE                VALUE               OPTION              COLLECTIONS
resource1           action              info                                    collection1
```

### Remove a resource from a collection
```bash
# hbm collection ls
NAME                TYPE                VALUE               OPTION              COLLECTIONS
resource1           action              info                                    collection1
# hbm resource member --remove collection1 resource1
# hbm collection ls
NAME                TYPE                VALUE               OPTION              COLLECTIONS
resource1           action              info
```

## Related information

* [resource_add](resource_add.md)
* [resource_find](resource_find.md)
* [resource_ls](resource_ls.md)
* [resource_rm](resource_rm.md)
