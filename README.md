# Usage

**Do not use `chainsaw-cut` outside the application container.**

These programmes allow you to optimise the size of the root file system that is
used by your application container. `chainsaw-whitelist` tracks all the files
that your application or service use and writes their absolute paths to
`whitelist` file.  `chainsaw-blacklist` scans root file system of your
application container and writes absolute paths of all files to `blacklist`
file. `chainsaw-diff` computes the set difference between the two files and
produces `diff` file that contains files that are not accessed by your
application. Please, review `diff` file carefully before running the final
command, **especially if you have mounted volumes inside your application
container**! The final command, `chainsaw-cut` deletes all the files specified by
absolute paths listed in `diff`.

General workflow is the following.
```bash
chainsaw-whitelist /bin/my-service  # generate a list of files that my-service reads/writes
chainsaw-blacklist /                # generate a list of all files in the root file system
chainsaw-diff                       # compute set difference between the two lists
chainsaw-cut                        # remove all the files from the resulting list
```

You can add files to whitelist and blacklist manually by appending to the
corresponding files.

You have several options to produce whitelist.
1. If your application is a service, you may consider running it with a timeout:
   ```bash
   chainsaw-whitelist timeout 1m /bin/my-service
   ```
2. If your application is a batch-processing programme, you may consider running it
   with some small input.
   ```bash
   chainsaw-whitelist /bin/my-simulation small-input.dat
   ```
3. If you can not figure out, how to run your application to produce correct whitelist,
   consider running it with a timeout and then append additional files manually.
   ```bash
   chainsaw-whitelist timeout 1m /bin/my-app
   find /opt/my-app -type f >> whitelist
   find /var/lib/my-app -type f >> whitelist
   echo /etc/passwd >> whitelist
   ```

# Installation

```bash
meson build
ninja -C build
sudo ninja -C build install
```
