# ifdef __cplusplus
extern "C" {
# endif

#include "../key_share.h"

# ifdef __cplusplus
}
# endif

#include <assert.h>
#include <stdio.h>
#include <string>
#include<iostream>

void test_share() {
    std::string input = "1c67f89bfd156ef37e33dd4cf0cdfccf899aaf12d";
    auto ret = share(input.data(), 1, 3);
    assert(ret);
    printf("ret: %s\n", ret);
    std::cout << "share test success!" << std::endl;

    str_free(ret);
}

void test_verify() {
    std::string input = "[{\"vss_scheme\":{\"parameters\":{\"threshold\":1,\"share_count\":3},\"commitments\":[{\"x\":\"13ba26ac16d22fd825d6bb2a45af76a81b682340f37a2cb971bf1fa6356f29e8\",\"y\":\"f5cf3d16257a1a14ad653577853d2ee55b40a563bb0351673d7d1b4f7a3eb578\"},{\"x\":\"ab17704c09193d476462fc90bfcb9f506d7eb1649a0c4a0e6940cec611f674e2\",\"y\":\"d644e1ce41cf35d060ba9ffdfca021e9ee0367afc60921507284d6cd157cb853\"}]},\"secret_share\":\"f2b1b915da12fd31986fffe689f4c36a428b2b879c0a9e5c259cbf2cbbdb00e1\",\"secret_share_indice\":0},{\"vss_scheme\":{\"parameters\":{\"threshold\":1,\"share_count\":3},\"commitments\":[{\"x\":\"c9923987d8506875bd459b3256e7819fa3d774aea10f16947d5549af71674f87\",\"y\":\"b7de6ee8d9ccfd25f5db1fc79f1e71794b8f17ccc7648a4a87ae0be03538062e\"},{\"x\":\"52ddd5d505a819783b957130e7043ed56fad5207f89a3366d418022d6e15ff96\",\"y\":\"f0fbcefd32bb6521e1876028e14df76bfe158f8b9c90fc0e4bec9da2b660f0ef\"}]},\"secret_share\":\"25712b6592dd40c51feb2259a85f769c3bf50c8c7098b366d98e2701d1710c1a\",\"secret_share_indice\":0}]";
    auto ret = verify(input.data());
    assert(ret);
    printf("ret: %d\n", ret);
    std::cout << "verify test success!" << std::endl;
}

void test_reconstruct() {
    std::string input = "[{\"vss_scheme\":{\"parameters\":{\"threshold\":1,\"share_count\":3},\"commitments\":[{\"x\":\"13ba26ac16d22fd825d6bb2a45af76a81b682340f37a2cb971bf1fa6356f29e8\",\"y\":\"f5cf3d16257a1a14ad653577853d2ee55b40a563bb0351673d7d1b4f7a3eb578\"},{\"x\":\"ab17704c09193d476462fc90bfcb9f506d7eb1649a0c4a0e6940cec611f674e2\",\"y\":\"d644e1ce41cf35d060ba9ffdfca021e9ee0367afc60921507284d6cd157cb853\"}]},\"secret_shares\":[\"f2b1b915da12fd31986fffe689f4c36a428b2b879c0a9e5c259cbf2cbbdb00e1\",\"e56340c87dee942af77d9968e2b45070643442c3559938185703b99c441b5a1e\"],\"secret_shares_indice\":[0,1]},{\"vss_scheme\":{\"parameters\":{\"threshold\":1,\"share_count\":3},\"commitments\":[{\"x\":\"c9923987d8506875bd459b3256e7819fa3d774aea10f16947d5549af71674f87\",\"y\":\"b7de6ee8d9ccfd25f5db1fc79f1e71794b8f17ccc7648a4a87ae0be03538062e\"},{\"x\":\"52ddd5d505a819783b957130e7043ed56fad5207f89a3366d418022d6e15ff96\",\"y\":\"f0fbcefd32bb6521e1876028e14df76bfe158f8b9c90fc0e4bec9da2b660f0ef\"}]},\"secret_shares\":[\"25712b6592dd40c51feb2259a85f769c3bf50c8c7098b366d98e2701d1710c1a\",\"4ae256cb25ba818a3fd644b350beed3877ea1918e0ce009579e2eca23cb0e5d0\"],\"secret_shares_indice\":[0,1]}]";
    auto ret = reconstruct(input.data());
    assert(ret);
    printf("ret: %s\n", ret);
    std::cout << "reconstruct test success!" << std::endl;

    str_free(ret);
}

void test_restore() {
    std::string input = "[{\"secret_shares\":[\"f2b1b915da12fd31986fffe689f4c36a428b2b879c0a9e5c259cbf2cbbdb00e1\",\"d814c87b21ca2b24568b32eb3b73dd7685dd59ff0f27d1d4886ab40bcc5bb35b\"],\"secret_shares_indice\":[0,2]},{\"secret_shares\":[\"25712b6592dd40c51feb2259a85f769c3bf50c8c7098b366d98e2701d1710c1a\",\"70538230b897c24f5fc1670cf91e63d4b3df25a551034dc41a37b242a7f0bf86\"],\"secret_shares_indice\":[0,2]}]";
    auto ret = restore(input.data(), 1);
    assert(ret);
    printf("ret: %s\n", ret);
    std::cout << "restore test success!" << std::endl;

    str_free(ret);
}

int main() {
    test_share();
    test_verify();
    test_reconstruct();
    test_restore();
    std::cout << "Test done!" << std::endl;
}
