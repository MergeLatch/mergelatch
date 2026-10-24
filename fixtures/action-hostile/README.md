# Hostile build files (fixture)

Every file here would leave a `HOSTILE_*` marker if a build tool or script
ever ran in this directory. The Action must scan this directory as data and
leave no marker. Nothing here is executed by MergeLatch's own tests.
