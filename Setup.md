
Source code is Compiled by this command

```=shell
gcc -O0 -fstack-protector -no-pie source.c -o bakait
```

Docker Setups commands

```=shell
docker build -t bakait .
```

```=shell
docker run -d --name bak -p 2568:2568 bakait
```

we can check server is running by
```=shell
nc localhost 2568
```



