# NestFuzz

NestFuzz is a structure-aware grey box fuzzer that developed based on AFL. It mainly includes two phases. 
In the first phase of input processing logic modeling, NestFuzz first leverages taint analysis to identify input-accessing instructions. Then, NestFuzz recognizes the inter-field dependencies and hierarchy dependencies by understanding the control- and data-flow relationships between these input-accessing instructions. Last, NestFuzz proposes a novel data structure, namely Input Processing Tree, that can represent the whole structure of the input format.
In the second phase of fuzzing, NestFuzz designs a cascading dependency-aware mutation strategy. Based on the recognized dependencies, whenever NestFuzz mutates (field or structure-level) the input, it cascadingly mutates other affected fields or substructures to maintain the structure validity. Therefore, NestFuzz can continuously and effectively generate new high-quality test cases.

For more details, welcome to follow our [paper](https://dl.acm.org/doi/abs/10.1145/3576915.3623103).
If you use NestFuzz in your science work, please use the following BibTeX entry:
```
@inproceedings{deng2023nestfuzz,
  title={NestFuzz: Enhancing Fuzzing with Comprehensive Understanding of Input Processing Logic},
  author={Deng, Peng and Yang, Zhemin and Zhang, Lei and Yang, Guangliang and Hong, Wenzheng and Zhang, Yuan and Yang, Min},
  booktitle={Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security},
  pages={1272--1286},
  year={2023}
}
```

## Build NestFuzz
Download NestFuzz with:
```
git clone https://github.com/fdu-sec/NestFuzz.git
```
### Build Fuzzer
```
cd NestFuzz
make
```

### Build Input Processing Logic Modeling
Please find the build requirements in the README.md file located at NestFuzz/ipl-modeling.
```
cd NestFuzz/ipl-modeling
./build.sh
```

## Usage
Step1: start the fuzzer:
```
./afl-fuzz -i input_dir -o fuzzer_output_dir -d -- /path/to/program [...params...]
```
Step2: start the input processing logic modeling:
```
python3 isi.py -t 60 -o fuzzer_output_dir -l fuzzer_output_dir/log -- /path/to/modeling_program [...params...]
```
## Example
Download the latest source code of libtiff:

```
git clone https://gitlab.com/libtiff/libtiff.git
```
Build the program for fuzzer:
```
cp -r libtiff libtiff-fuzzer
cd libtiff-fuzzer
./autogen.sh
CC=/path/to/NestFuzz/afl-gcc CXX=/path/to/NestFuzz/afl-g++ ./configure --disable-shared
make -j$(nproc)
```
Build the program for input processing logic modeling:
```
cp -r libtiff libtiff-model
cd libtiff-model
./autogen.sh
CC=/path/to/NestFuzz/ipl-modeling/install/test-clang CXX=/path/to/NestFuzz/ipl-modeling/install/test-clang++ ./configure --disable-shared
make -j$(nproc)
```
Start the fuzzer:
```
/path/to/NestFuzz/afl-fuzz -m none -d -i /path/to/NestFuzz/testcases/images/tiff -o tiff_output -- /path/to/libtiff-fuzzer/tools/tiffsplit @@
```
Start the input processing logic modeling:
```
python3 /path/to/NestFuzz/isi.py -t 60 -o /path/to/tiff_output -l /path/to/tiff_output/log -- /path/to/libtiff-model/tools/tiffsplit @@
```
## 🏆Vulnerabilities Found by NestFuzz
|  ID  |  CVE ID        | Software | CVSS Score |
| :---:  | :--------------: | :------: | :---: |
|  1   | CVE-2022-40438 | Bento4 | 6.5 MEDIUM |
|  2   | CVE-2022-40439 | Bento4 | 6.5 MEDIUM |
|  3   | CVE-2022-43032 | Bento4 | 6.5 MEDIUM |
|  4   | CVE-2022-43033 | Bento4 | 6.5 MEDIUM |
|  5   | CVE-2022-43034 | Bento4 | 6.5 MEDIUM |
|  6   | CVE-2022-43035 | Bento4 | 6.5 MEDIUM |
|  7   | CVE-2022-43037 | Bento4 | 6.5 MEDIUM |
|  8   | CVE-2022-43038 | Bento4 | 6.5 MEDIUM |
|  9   | CVE-2022-43039 | GPAC | 5.5 MEDIUM |
|  10   | CVE-2022-43040 | GPAC | 7.8 HIGH |
|  11   | CVE-2022-43042 | GPAC | 7.8 HIGH |
|  12   | CVE-2022-43043 | GPAC | 5.5 MEDIUM |
|  13   | CVE-2022-43044 | GPAC | 5.5 MEDIUM |
|  14   | CVE-2022-43045 | GPAC | 5.5 MEDIUM |
|  15   | CVE-2022-43254 | GPAC | 5.5 MEDIUM |
|  16   | CVE-2022-43255 | GPAC | 5.5 MEDIUM |
|  17   | CVE-2022-43235 | libde265 | 6.5 MEDIUM |
|  18   | CVE-2022-43236 | libde265 | 6.5 MEDIUM |
|  19   | CVE-2022-43237 | libde265 | 6.5 MEDIUM |
|  20   | CVE-2022-43238 | libde265 | 6.5 MEDIUM |
|  21   | CVE-2022-43239 | libde265 | 6.5 MEDIUM |
|  22   | CVE-2022-43240 | libde265 | 6.5 MEDIUM |
|  23   | CVE-2022-43241 | libde265 | 6.5 MEDIUM |
|  24   | CVE-2022-43242 | libde265 | 6.5 MEDIUM |
|  25   | CVE-2022-43243 | libde265 | 6.5 MEDIUM |
|  26   | CVE-2022-43244 | libde265 | 6.5 MEDIUM |
|  27   | CVE-2022-43245 | libde265 | 6.5 MEDIUM |
|  28   | CVE-2022-43248 | libde265 | 6.5 MEDIUM |
|  29   | CVE-2022-43249 | libde265 | 6.5 MEDIUM |
|  30   | CVE-2022-43250 | libde265 | 6.5 MEDIUM |
|  31   | CVE-2022-43252 | libde265 | 6.5 MEDIUM |
|  32   | CVE-2022-43253 | libde265 | 6.5 MEDIUM |
|  33   | CVE-2022-47069 | pzip | 7.8 HIGH |
|  34   | CVE-2022-48063 | binutils | 5.5 MEDIUM |
|  35   | CVE-2022-48064 | binutils | 5.5 MEDIUM |
|  36   | CVE-2022-48065 | binutils | 5.5 MEDIUM |
|  37   | CVE-2022-37115 | ncurses  | reserved   | 
|  38   | CVE-2023-6350  | libavif | 8.8 HIGH |
|  39   | CVE-2023-6351  | libavif | 8.8 HIGH |
|  40   | CVE-2023-6704  | libavif | 8.8 HIGH |
|  41   | CVE-2023-49460 | libheif | 8.8 HIGH |
|  42   | CVE-2023-49462 | libheif | 8.8 HIGH |
|  43   | CVE-2023-49463 | libheif | 8.8 HIGH |
|  44   | CVE-2023-49464 | libheif | 8.8 HIGH |
|  45   | CVE-2024-31619 | libheif | reserved |
|  46   | CVE-2023-48106 | minizip | 8.8 HIGH |
|  47   | CVE-2023-48107 | minizip | 8.8 HIGH |
|  48   | CVE-2023-40305 | indent  | 5.5 MEDIUM |
|  49   | CVE-2023-39070 | Cppcheck | 7.8 HIGH |
|  50   | CVE-2023-49465 | libde265 | 8.8 HIGH |
|  51   | CVE-2023-49467 | libde265 | 8.8 HIGH |
|  52   | CVE-2023-49468 | libde265 | 8.8 HIGH |
