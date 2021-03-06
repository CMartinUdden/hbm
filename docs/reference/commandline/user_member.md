---
description: The user member command description and usage
keywords:
- user, member
menu:
  main:
    parent: smn_cli
title: user member
---

# hbm user member
***

```markdown
Manage user membership to group

Usage:
  hbm user member [group] [name] [flags]

Flags:
  -a, --add      Add user to group
  -r, --remove   Remove user from group
```

## Examples

### Add a user to a group
```bash
# hbm user ls
NAME                GROUPS
user1
# hbm user member --add group1 user1
# hbm user ls
NAME                GROUPS
user1               group1
```

### Remove a user from a group
```bash
# hbm user ls
NAME                GROUPS
user1               group1
# hbm user member --remove group1 user1
# hbm user ls
NAME                GROUPS
user1
```

## Related information

* [user_add](user_add.md)
* [user_find](user_find.md)
* [user_ls](user_ls.md)
* [user_rm](user_rm.md)
