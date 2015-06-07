
# idascript

Console mode IDA script launcher with stdin/stdout handled. A pty is used to pass stdin/stdout, so you can directly view your stdout/stderr in the same terminal. There is no need to write to a file and cat it later.

Inspired by [hexray blog](http://www.hexblog.com/?p=128) and [https://code.google.com/p/idascript/](https://code.google.com/p/idascript/)

## Example

    $ idascript your.idb example.py 

The result is like this.

![Example Screenshot](scrot.png)

## ida launcher

ida is a script to launch IDA or IDA 64 from commandline.

    $ ida mybin.exe
    $ ida elf64  # will launch IDA Pro 64 if told elf64 by file command
    $ ida xxx.idb
    $ ida xxx.i64 # will launch IDA Pro 64

## Configuration

Just change the `IDA_PATH` variable to your installation path.

## Dependency

- python2
- termcolor(optional)

if you need colored output, install `termcolor` beforehand

    $ sudo pip install termcolor
