#ifndef _TEST_H_
#define _TEST_H_

#include <stdint.h>

/**
 * @brief 打印内存数据
 *
 * @param ptr
 * @param len
 */
void dump_mem(const void* ptr, int len);
/**
 * @brief 16进制字符串转数组
 *
 * @param str 16进制字符串
 * @param len 字节串长度(in Byte)
 * @param out 输出
 */
void HexString2Hex(const char* str, int len, uint8_t* out);

/**
 * Prints the binary representation of the given byte array.
 *
 * @param ptr pointer to the byte array to be printed
 * @param len length of the byte array
 *
 * @return void
 *
 * @throws None
 */
void print_binary(const uint8_t* ptr, int len);

/**
 * @brief 打印u8数组
 *
 * @param title  标题
 * @param ptr    u8数组
 * @param len    u8数组的长度
 *
 * @return void
 *
 * @example
 * uint8_t arr[10] = {
 *     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
 * };
 * print_u8("arr", arr, 10);
 * //  output:
 * uint8_t arr[10] = {
 *     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
 * };
 */
void print_u8(const char* title, const uint8_t* ptr, size_t len);

/**
 * @brief 打印u32数组
 *
 * @param title  标题
 * @param ptr    u32数组
 * @param len    u32数组的长度
 *
 * @return void
 *
 * @example
 * uint32_t arr[10] = {
 *     0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080,
 *     0x00000100, 0x00000200
 * };
 * print_u32("arr", arr, 10);
 * //  output:
 * uint32_t arr[10] = {
 *     0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080,
 *     0x00000100, 0x00000200
 * };
 */
void print_u32(const char* title, const uint32_t* ptr, size_t len);

/**
 * @brief  u64
 *
 * @param title  标题
 * @param ptr    u64数组
 * @param len    u64数组的长度
 *
 * @return void
 *
 * @example
 * uint64_t arr[10] = {
 *     0x0000000000000001, 0x0000000000000002, 0x0000000000000004, 0x0000000000000008, 0x0000000000000010, 0x0000000000000020, 0x0000000000000040, 0x0000000000000080,
 *     0x0000000000000100, 0x0000000000000200
 * };
 * print_u64("arr", arr, 10);
 * //  output:
 * uint64_t arr[10] = {
 *     0x0000000000000001, 0x0000000000000002, 0x0000000000000004, 0x0000000000000008,
 *     0x0000000000000010, 0x0000000000000020, 0x0000000000000040, 0x0000000000000080,
 *     0x0000000000000100, 0x0000000000000200
 * };
 */
void print_u64(const char* title, const uint64_t* ptr, size_t len);

#endif // _TEST_H_