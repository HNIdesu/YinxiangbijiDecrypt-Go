# YinxiangbijiDecrypt
## Introduction
Yinxiangbijidecrypt-Go is a Go implementation of the YinxiangbijiConverter, a tool designed to decrypt and convert encrypted Yinxiangbiji (Evernote China) files. This project enables users to handle encrypted note files, decrypt the content, and make necessary modifications.

## Usage
To use the tool, simply run the following command:

```bash
go run yinxiangbijidecrypt.go <filepath|directory>
```

- `<filepath>`: Path to a single encrypted file you want to decrypt.
- `<directory>`: Path to a directory containing multiple encrypted files.

The tool will process and decrypt all relevant files automatically.

## Dependencies

Before compiling and running the project, ensure that the following dependencies are installed:

- **github.com/antchfx/xmlquery**: This library is used for XML querying and manipulation.

You can install the dependency using:

```bash
go get github.com/antchfx/xmlquery
```

## License
This project is licensed under the [GPLv3 License](https://www.gnu.org/licenses/gpl-3.0.html). For more details, see the `LICENSE` file.