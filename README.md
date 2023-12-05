# NestFuzz

NestFuzz is a structure-aware grey box fuzzer that developed based on AFL. It mainly includes two phases. 
In the first phase of input processing logic modeling, NestFuzz first leverages taint analysis to identify input-accessing instructions. Then, NestFuzz recognizes the inter-field dependencies and hierarchy dependencies by understanding the control- and data-flow relationships between these input-accessing instructions. Last, NestFuzz proposes a novel data structure, namely Input Processing Tree, that can represent the whole structure of the input format.
In the second phase of fuzzing, NestFuzz designs a cascading dependency-aware mutation strategy. Based on the recognized dependencies, whenever NestFuzz mutates (field or structure-level) the input, it cascadingly mutates other affected fields or substructures to maintain the structure validity. Therefore, NestFuzz can continuously and effectively generate new high-quality test cases.

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
## Cite
If you use NestFuzz in your science work, please cite our paper:
```
@inproceedings{deng2023nestfuzz,
  title={NestFuzz: Enhancing Fuzzing with Comprehensive Understanding of Input Processing Logic},
  author={Deng, Peng and Yang, Zhemin and Zhang, Lei and Yang, Guangliang and Hong, Wenzheng and Zhang, Yuan and Yang, Min},
  booktitle={Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security},
  pages={1272--1286},
  year={2023}
}
```
