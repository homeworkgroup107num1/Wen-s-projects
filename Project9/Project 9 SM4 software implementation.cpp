#include <iostream>
#include <stdint.h>
#include <windows.h>  
#include <iomanip>
#include <time.h>
using namespace std;

//参数定义

//S盒
//用于密钥扩展的S盒
static const uint32_t S_Box[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48 };
//用于加解密的S盒0
static const uint32_t S_Box0[256] = {
    0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787,
    0xC93DF4F4, 0x6BB5DEDE, 0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B,
    0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414, 0x872BACAC, 0xFB669D9D,
    0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
    0x02A8AAAA, 0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A,
    0x1E061818, 0xFD9B6666, 0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3,
    0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9, 0xFF33CCCC, 0x04555151,
    0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
    0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020,
    0x48EBA3A3, 0xC1975656, 0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB,
    0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A, 0x5B461D1D, 0x1B071C1C,
    0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
    0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616,
    0x734E3D3D, 0x08AAA2A2, 0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA,
    0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E, 0x18FBE3E3, 0x47E8AFAF,
    0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4,
    0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161,
    0x95D24747, 0x2AA08A8A, 0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC,
    0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E, 0x84D75353, 0x00000000,
    0x5E471919, 0x0B565D5D, 0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
    0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313,
    0xE8CB2323, 0xE69C7A7A, 0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B,
    0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6, 0x2FA18E8E, 0x2BF4DFDF,
    0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
    0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0,
    0x721A6868, 0x01545555, 0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0,
    0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F, 0x691D7474, 0x2EF5DBDB,
    0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
    0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x07A9AEAE, 0x390D3434, 0x1F524D4D,
    0x764F3939, 0xD36EBDBD, 0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515,
    0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC, 0x0F030C0C, 0x03FCFFFF,
    0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
    0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777,
    0x4CBEF2F2, 0x837EFDFD, 0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505,
    0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363, 0x220A2828, 0xC5C20707,
    0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
    0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797,
    0x64B6D2D2, 0x70B2C2C2, 0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929,
    0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9, 0xF1649595, 0x5DBBE6E6,
    0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
    0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373,
    0x794C3535, 0xA0208080, 0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8,
    0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121 };
//用于加解密的S盒1
static const uint32_t S_Box1[256] = {
    0x5B8ED55B, 0x42D09242, 0xA74DEAA7, 0xFB06FDFB, 0x33FCCF33, 0x8765E287,
    0xF4C93DF4, 0xDE6BB5DE, 0x584E1658, 0xDA6EB4DA, 0x50441450, 0x0BCAC10B,
    0xA08828A0, 0xEF17F8EF, 0xB09C2CB0, 0x14110514, 0xAC872BAC, 0x9DFB669D,
    0x6AF2986A, 0xD9AE77D9, 0xA8822AA8, 0xFA46BCFA, 0x10140410, 0x0FCFC00F,
    0xAA02A8AA, 0x11544511, 0x4C5F134C, 0x98BE2698, 0x256D4825, 0x1A9E841A,
    0x181E0618, 0x66FD9B66, 0x72EC9E72, 0x094A4309, 0x41105141, 0xD324F7D3,
    0x46D59346, 0xBF53ECBF, 0x62F89A62, 0xE9927BE9, 0xCCFF33CC, 0x51045551,
    0x2C270B2C, 0x0D4F420D, 0xB759EEB7, 0x3FF3CC3F, 0xB21CAEB2, 0x89EA6389,
    0x9374E793, 0xCE7FB1CE, 0x706C1C70, 0xA60DABA6, 0x27EDCA27, 0x20280820,
    0xA348EBA3, 0x56C19756, 0x02808202, 0x7FA3DC7F, 0x52C49652, 0xEB12F9EB,
    0xD5A174D5, 0x3EB38D3E, 0xFCC33FFC, 0x9A3EA49A, 0x1D5B461D, 0x1C1B071C,
    0x9E3BA59E, 0xF30CFFF3, 0xCF3FF0CF, 0xCDBF72CD, 0x5C4B175C, 0xEA52B8EA,
    0x0E8F810E, 0x653D5865, 0xF0CC3CF0, 0x647D1964, 0x9B7EE59B, 0x16918716,
    0x3D734E3D, 0xA208AAA2, 0xA1C869A1, 0xADC76AAD, 0x06858306, 0xCA7AB0CA,
    0xC5B570C5, 0x91F46591, 0x6BB2D96B, 0x2EA7892E, 0xE318FBE3, 0xAF47E8AF,
    0x3C330F3C, 0x2D674A2D, 0xC1B071C1, 0x590E5759, 0x76E99F76, 0xD4E135D4,
    0x78661E78, 0x90B42490, 0x38360E38, 0x79265F79, 0x8DEF628D, 0x61385961,
    0x4795D247, 0x8A2AA08A, 0x94B12594, 0x88AA2288, 0xF18C7DF1, 0xECD73BEC,
    0x04050104, 0x84A52184, 0xE19879E1, 0x1E9B851E, 0x5384D753, 0x00000000,
    0x195E4719, 0x5D0B565D, 0x7EE39D7E, 0x4F9FD04F, 0x9CBB279C, 0x491A5349,
    0x317C4D31, 0xD8EE36D8, 0x080A0208, 0x9F7BE49F, 0x8220A282, 0x13D4C713,
    0x23E8CB23, 0x7AE69C7A, 0xAB42E9AB, 0xFE43BDFE, 0x2AA2882A, 0x4B9AD14B,
    0x01404101, 0x1FDBC41F, 0xE0D838E0, 0xD661B7D6, 0x8E2FA18E, 0xDF2BF4DF,
    0xCB3AF1CB, 0x3BF6CD3B, 0xE71DFAE7, 0x85E56085, 0x54411554, 0x8625A386,
    0x8360E383, 0xBA16ACBA, 0x75295C75, 0x9234A692, 0x6EF7996E, 0xD0E434D0,
    0x68721A68, 0x55015455, 0xB619AFB6, 0x4EDF914E, 0xC8FA32C8, 0xC0F030C0,
    0xD721F6D7, 0x32BC8E32, 0xC675B3C6, 0x8F6FE08F, 0x74691D74, 0xDB2EF5DB,
    0x8B6AE18B, 0xB8962EB8, 0x0A8A800A, 0x99FE6799, 0x2BE2C92B, 0x81E06181,
    0x03C0C303, 0xA48D29A4, 0x8CAF238C, 0xAE07A9AE, 0x34390D34, 0x4D1F524D,
    0x39764F39, 0xBDD36EBD, 0x5781D657, 0x6FB7D86F, 0xDCEB37DC, 0x15514415,
    0x7BA6DD7B, 0xF709FEF7, 0x3AB68C3A, 0xBC932FBC, 0x0C0F030C, 0xFF03FCFF,
    0xA9C26BA9, 0xC9BA73C9, 0xB5D96CB5, 0xB1DC6DB1, 0x6D375A6D, 0x45155045,
    0x36B98F36, 0x6C771B6C, 0xBE13ADBE, 0x4ADA904A, 0xEE57B9EE, 0x77A9DE77,
    0xF24CBEF2, 0xFD837EFD, 0x44551144, 0x67BDDA67, 0x712C5D71, 0x05454005,
    0x7C631F7C, 0x40501040, 0x69325B69, 0x63B8DB63, 0x28220A28, 0x07C5C207,
    0xC4F531C4, 0x22A88A22, 0x9631A796, 0x37F9CE37, 0xED977AED, 0xF649BFF6,
    0xB4992DB4, 0xD1A475D1, 0x4390D343, 0x485A1248, 0xE258BAE2, 0x9771E697,
    0xD264B6D2, 0xC270B2C2, 0x26AD8B26, 0xA5CD68A5, 0x5ECB955E, 0x29624B29,
    0x303C0C30, 0x5ACE945A, 0xDDAB76DD, 0xF9867FF9, 0x95F16495, 0xE65DBBE6,
    0xC735F2C7, 0x242D0924, 0x17D1C617, 0xB9D66FB9, 0x1BDEC51B, 0x12948612,
    0x60781860, 0xC330F3C3, 0xF5897CF5, 0xB35CEFB3, 0xE8D23AE8, 0x73ACDF73,
    0x35794C35, 0x80A02080, 0xE59D78E5, 0xBB56EDBB, 0x7D235E7D, 0xF8C63EF8,
    0x5F8BD45F, 0x2FE7C82F, 0xE4DD39E4, 0x21684921 };
//用于加解密的S盒2
static const uint32_t S_Box2[256] = {
    0x5B5B8ED5, 0x4242D092, 0xA7A74DEA, 0xFBFB06FD, 0x3333FCCF, 0x878765E2,
    0xF4F4C93D, 0xDEDE6BB5, 0x58584E16, 0xDADA6EB4, 0x50504414, 0x0B0BCAC1,
    0xA0A08828, 0xEFEF17F8, 0xB0B09C2C, 0x14141105, 0xACAC872B, 0x9D9DFB66,
    0x6A6AF298, 0xD9D9AE77, 0xA8A8822A, 0xFAFA46BC, 0x10101404, 0x0F0FCFC0,
    0xAAAA02A8, 0x11115445, 0x4C4C5F13, 0x9898BE26, 0x25256D48, 0x1A1A9E84,
    0x18181E06, 0x6666FD9B, 0x7272EC9E, 0x09094A43, 0x41411051, 0xD3D324F7,
    0x4646D593, 0xBFBF53EC, 0x6262F89A, 0xE9E9927B, 0xCCCCFF33, 0x51510455,
    0x2C2C270B, 0x0D0D4F42, 0xB7B759EE, 0x3F3FF3CC, 0xB2B21CAE, 0x8989EA63,
    0x939374E7, 0xCECE7FB1, 0x70706C1C, 0xA6A60DAB, 0x2727EDCA, 0x20202808,
    0xA3A348EB, 0x5656C197, 0x02028082, 0x7F7FA3DC, 0x5252C496, 0xEBEB12F9,
    0xD5D5A174, 0x3E3EB38D, 0xFCFCC33F, 0x9A9A3EA4, 0x1D1D5B46, 0x1C1C1B07,
    0x9E9E3BA5, 0xF3F30CFF, 0xCFCF3FF0, 0xCDCDBF72, 0x5C5C4B17, 0xEAEA52B8,
    0x0E0E8F81, 0x65653D58, 0xF0F0CC3C, 0x64647D19, 0x9B9B7EE5, 0x16169187,
    0x3D3D734E, 0xA2A208AA, 0xA1A1C869, 0xADADC76A, 0x06068583, 0xCACA7AB0,
    0xC5C5B570, 0x9191F465, 0x6B6BB2D9, 0x2E2EA789, 0xE3E318FB, 0xAFAF47E8,
    0x3C3C330F, 0x2D2D674A, 0xC1C1B071, 0x59590E57, 0x7676E99F, 0xD4D4E135,
    0x7878661E, 0x9090B424, 0x3838360E, 0x7979265F, 0x8D8DEF62, 0x61613859,
    0x474795D2, 0x8A8A2AA0, 0x9494B125, 0x8888AA22, 0xF1F18C7D, 0xECECD73B,
    0x04040501, 0x8484A521, 0xE1E19879, 0x1E1E9B85, 0x535384D7, 0x00000000,
    0x19195E47, 0x5D5D0B56, 0x7E7EE39D, 0x4F4F9FD0, 0x9C9CBB27, 0x49491A53,
    0x31317C4D, 0xD8D8EE36, 0x08080A02, 0x9F9F7BE4, 0x828220A2, 0x1313D4C7,
    0x2323E8CB, 0x7A7AE69C, 0xABAB42E9, 0xFEFE43BD, 0x2A2AA288, 0x4B4B9AD1,
    0x01014041, 0x1F1FDBC4, 0xE0E0D838, 0xD6D661B7, 0x8E8E2FA1, 0xDFDF2BF4,
    0xCBCB3AF1, 0x3B3BF6CD, 0xE7E71DFA, 0x8585E560, 0x54544115, 0x868625A3,
    0x838360E3, 0xBABA16AC, 0x7575295C, 0x929234A6, 0x6E6EF799, 0xD0D0E434,
    0x6868721A, 0x55550154, 0xB6B619AF, 0x4E4EDF91, 0xC8C8FA32, 0xC0C0F030,
    0xD7D721F6, 0x3232BC8E, 0xC6C675B3, 0x8F8F6FE0, 0x7474691D, 0xDBDB2EF5,
    0x8B8B6AE1, 0xB8B8962E, 0x0A0A8A80, 0x9999FE67, 0x2B2BE2C9, 0x8181E061,
    0x0303C0C3, 0xA4A48D29, 0x8C8CAF23, 0xAEAE07A9, 0x3434390D, 0x4D4D1F52,
    0x3939764F, 0xBDBDD36E, 0x575781D6, 0x6F6FB7D8, 0xDCDCEB37, 0x15155144,
    0x7B7BA6DD, 0xF7F709FE, 0x3A3AB68C, 0xBCBC932F, 0x0C0C0F03, 0xFFFF03FC,
    0xA9A9C26B, 0xC9C9BA73, 0xB5B5D96C, 0xB1B1DC6D, 0x6D6D375A, 0x45451550,
    0x3636B98F, 0x6C6C771B, 0xBEBE13AD, 0x4A4ADA90, 0xEEEE57B9, 0x7777A9DE,
    0xF2F24CBE, 0xFDFD837E, 0x44445511, 0x6767BDDA, 0x71712C5D, 0x05054540,
    0x7C7C631F, 0x40405010, 0x6969325B, 0x6363B8DB, 0x2828220A, 0x0707C5C2,
    0xC4C4F531, 0x2222A88A, 0x969631A7, 0x3737F9CE, 0xEDED977A, 0xF6F649BF,
    0xB4B4992D, 0xD1D1A475, 0x434390D3, 0x48485A12, 0xE2E258BA, 0x979771E6,
    0xD2D264B6, 0xC2C270B2, 0x2626AD8B, 0xA5A5CD68, 0x5E5ECB95, 0x2929624B,
    0x30303C0C, 0x5A5ACE94, 0xDDDDAB76, 0xF9F9867F, 0x9595F164, 0xE6E65DBB,
    0xC7C735F2, 0x24242D09, 0x1717D1C6, 0xB9B9D66F, 0x1B1BDEC5, 0x12129486,
    0x60607818, 0xC3C330F3, 0xF5F5897C, 0xB3B35CEF, 0xE8E8D23A, 0x7373ACDF,
    0x3535794C, 0x8080A020, 0xE5E59D78, 0xBBBB56ED, 0x7D7D235E, 0xF8F8C63E,
    0x5F5F8BD4, 0x2F2FE7C8, 0xE4E4DD39, 0x21216849 };
//加解密S盒3
static const uint32_t S_Box3[256] = {
    0xD55B5B8E, 0x924242D0, 0xEAA7A74D, 0xFDFBFB06, 0xCF3333FC, 0xE2878765,
    0x3DF4F4C9, 0xB5DEDE6B, 0x1658584E, 0xB4DADA6E, 0x14505044, 0xC10B0BCA,
    0x28A0A088, 0xF8EFEF17, 0x2CB0B09C, 0x05141411, 0x2BACAC87, 0x669D9DFB,
    0x986A6AF2, 0x77D9D9AE, 0x2AA8A882, 0xBCFAFA46, 0x04101014, 0xC00F0FCF,
    0xA8AAAA02, 0x45111154, 0x134C4C5F, 0x269898BE, 0x4825256D, 0x841A1A9E,
    0x0618181E, 0x9B6666FD, 0x9E7272EC, 0x4309094A, 0x51414110, 0xF7D3D324,
    0x934646D5, 0xECBFBF53, 0x9A6262F8, 0x7BE9E992, 0x33CCCCFF, 0x55515104,
    0x0B2C2C27, 0x420D0D4F, 0xEEB7B759, 0xCC3F3FF3, 0xAEB2B21C, 0x638989EA,
    0xE7939374, 0xB1CECE7F, 0x1C70706C, 0xABA6A60D, 0xCA2727ED, 0x08202028,
    0xEBA3A348, 0x975656C1, 0x82020280, 0xDC7F7FA3, 0x965252C4, 0xF9EBEB12,
    0x74D5D5A1, 0x8D3E3EB3, 0x3FFCFCC3, 0xA49A9A3E, 0x461D1D5B, 0x071C1C1B,
    0xA59E9E3B, 0xFFF3F30C, 0xF0CFCF3F, 0x72CDCDBF, 0x175C5C4B, 0xB8EAEA52,
    0x810E0E8F, 0x5865653D, 0x3CF0F0CC, 0x1964647D, 0xE59B9B7E, 0x87161691,
    0x4E3D3D73, 0xAAA2A208, 0x69A1A1C8, 0x6AADADC7, 0x83060685, 0xB0CACA7A,
    0x70C5C5B5, 0x659191F4, 0xD96B6BB2, 0x892E2EA7, 0xFBE3E318, 0xE8AFAF47,
    0x0F3C3C33, 0x4A2D2D67, 0x71C1C1B0, 0x5759590E, 0x9F7676E9, 0x35D4D4E1,
    0x1E787866, 0x249090B4, 0x0E383836, 0x5F797926, 0x628D8DEF, 0x59616138,
    0xD2474795, 0xA08A8A2A, 0x259494B1, 0x228888AA, 0x7DF1F18C, 0x3BECECD7,
    0x01040405, 0x218484A5, 0x79E1E198, 0x851E1E9B, 0xD7535384, 0x00000000,
    0x4719195E, 0x565D5D0B, 0x9D7E7EE3, 0xD04F4F9F, 0x279C9CBB, 0x5349491A,
    0x4D31317C, 0x36D8D8EE, 0x0208080A, 0xE49F9F7B, 0xA2828220, 0xC71313D4,
    0xCB2323E8, 0x9C7A7AE6, 0xE9ABAB42, 0xBDFEFE43, 0x882A2AA2, 0xD14B4B9A,
    0x41010140, 0xC41F1FDB, 0x38E0E0D8, 0xB7D6D661, 0xA18E8E2F, 0xF4DFDF2B,
    0xF1CBCB3A, 0xCD3B3BF6, 0xFAE7E71D, 0x608585E5, 0x15545441, 0xA3868625,
    0xE3838360, 0xACBABA16, 0x5C757529, 0xA6929234, 0x996E6EF7, 0x34D0D0E4,
    0x1A686872, 0x54555501, 0xAFB6B619, 0x914E4EDF, 0x32C8C8FA, 0x30C0C0F0,
    0xF6D7D721, 0x8E3232BC, 0xB3C6C675, 0xE08F8F6F, 0x1D747469, 0xF5DBDB2E,
    0xE18B8B6A, 0x2EB8B896, 0x800A0A8A, 0x679999FE, 0xC92B2BE2, 0x618181E0,
    0xC30303C0, 0x29A4A48D, 0x238C8CAF, 0xA9AEAE07, 0x0D343439, 0x524D4D1F,
    0x4F393976, 0x6EBDBDD3, 0xD6575781, 0xD86F6FB7, 0x37DCDCEB, 0x44151551,
    0xDD7B7BA6, 0xFEF7F709, 0x8C3A3AB6, 0x2FBCBC93, 0x030C0C0F, 0xFCFFFF03,
    0x6BA9A9C2, 0x73C9C9BA, 0x6CB5B5D9, 0x6DB1B1DC, 0x5A6D6D37, 0x50454515,
    0x8F3636B9, 0x1B6C6C77, 0xADBEBE13, 0x904A4ADA, 0xB9EEEE57, 0xDE7777A9,
    0xBEF2F24C, 0x7EFDFD83, 0x11444455, 0xDA6767BD, 0x5D71712C, 0x40050545,
    0x1F7C7C63, 0x10404050, 0x5B696932, 0xDB6363B8, 0x0A282822, 0xC20707C5,
    0x31C4C4F5, 0x8A2222A8, 0xA7969631, 0xCE3737F9, 0x7AEDED97, 0xBFF6F649,
    0x2DB4B499, 0x75D1D1A4, 0xD3434390, 0x1248485A, 0xBAE2E258, 0xE6979771,
    0xB6D2D264, 0xB2C2C270, 0x8B2626AD, 0x68A5A5CD, 0x955E5ECB, 0x4B292962,
    0x0C30303C, 0x945A5ACE, 0x76DDDDAB, 0x7FF9F986, 0x649595F1, 0xBBE6E65D,
    0xF2C7C735, 0x0924242D, 0xC61717D1, 0x6FB9B9D6, 0xC51B1BDE, 0x86121294,
    0x18606078, 0xF3C3C330, 0x7CF5F589, 0xEFB3B35C, 0x3AE8E8D2, 0xDF7373AC,
    0x4C353579, 0x208080A0, 0x78E5E59D, 0xEDBBBB56, 0x5E7D7D23, 0x3EF8F8C6,
    0xD45F5F8B, 0xC82F2FE7, 0x39E4E4DD, 0x49212168 };
//用于密钥扩展优化的S盒0
static const unsigned int SS_Box0[256] = {
    0xd66b1ac0, 0x90481200, 0xe9749d20, 0xfe7f1fc0, 0xcc661980, 0xe1709c20,
    0x3d1e87a0, 0xb75b96e0, 0x160b02c0, 0xb65b16c0, 0x140a0280, 0xc2611840,
    0x28140500, 0xfb7d9f60, 0x2c160580, 0x50280a0, 0x2b158560, 0x67338ce0,
    0x9a4d1340, 0x763b0ec0, 0x2a150540, 0xbe5f17c0, 0x4020080, 0xc3619860,
    0xaa551540, 0x44220880, 0x13098260, 0x261304c0, 0x49248920, 0x864310c0,
    0x60300c0, 0x994c9320, 0x9c4e1380, 0x42210840, 0x50280a00, 0xf47a1e80,
    0x91489220, 0xef779de0, 0x984c1300, 0x7a3d0f40, 0x33198660, 0x542a0a80,
    0xb058160, 0x43218860, 0xed769da0, 0xcf6799e0, 0xac561580, 0x62310c40,
    0xe4721c80, 0xb3599660, 0x1c0e0380, 0xa9549520, 0xc9649920, 0x8040100,
    0xe8741d00, 0x954a92a0, 0x80401000, 0xdf6f9be0, 0x944a1280, 0xfa7d1f40,
    0x753a8ea0, 0x8f4791e0, 0x3f1f87e0, 0xa65314c0, 0x472388e0, 0x70380e0,
    0xa75394e0, 0xfc7e1f80, 0xf3799e60, 0x73398e60, 0x170b82e0, 0xba5d1740,
    0x83419060, 0x592c8b20, 0x3c1e0780, 0x190c8320, 0xe6731cc0, 0x854290a0,
    0x4f2789e0, 0xa8541500, 0x68340d00, 0x6b358d60, 0x81409020, 0xb2591640,
    0x71388e20, 0x64320c80, 0xda6d1b40, 0x8b459160, 0xf87c1f00, 0xeb759d60,
    0xf0781e0, 0x4b258960, 0x70380e00, 0x562b0ac0, 0x9d4e93a0, 0x351a86a0,
    0x1e0f03c0, 0x24120480, 0xe0701c0, 0x5e2f0bc0, 0x63318c60, 0x582c0b00,
    0xd1689a20, 0xa2511440, 0x251284a0, 0x22110440, 0x7c3e0f80, 0x3b1d8760,
    0x1008020, 0x21108420, 0x783c0f00, 0x874390e0, 0xd46a1a80, 0x0,
    0x462308c0, 0x572b8ae0, 0x9f4f93e0, 0xd3699a60, 0x271384e0, 0x52290a40,
    0x4c260980, 0x361b06c0, 0x2010040, 0xe7739ce0, 0xa0501400, 0xc4621880,
    0xc8641900, 0x9e4f13c0, 0xea751d40, 0xbf5f97e0, 0x8a451140, 0xd2691a40,
    0x40200800, 0xc76398e0, 0x381c0700, 0xb55a96a0, 0xa3519460, 0xf77b9ee0,
    0xf2791e40, 0xce6719c0, 0xf97c9f20, 0x61308c20, 0x150a82a0, 0xa1509420,
    0xe0701c00, 0xae5715c0, 0x5d2e8ba0, 0xa4521480, 0x9b4d9360, 0x341a0680,
    0x1a0d0340, 0x552a8aa0, 0xad5695a0, 0x93499260, 0x32190640, 0x30180600,
    0xf57a9ea0, 0x8c461180, 0xb1589620, 0xe3719c60, 0x1d0e83a0, 0xf67b1ec0,
    0xe2711c40, 0x2e1705c0, 0x82411040, 0x66330cc0, 0xca651940, 0x60300c00,
    0xc0601800, 0x29148520, 0x23118460, 0xab559560, 0xd0681a0, 0x53298a60,
    0x4e2709c0, 0x6f378de0, 0xd56a9aa0, 0xdb6d9b60, 0x371b86e0, 0x452288a0,
    0xde6f1bc0, 0xfd7e9fa0, 0x8e4711c0, 0x2f1785e0, 0x3018060, 0xff7f9fe0,
    0x6a350d40, 0x72390e40, 0x6d368da0, 0x6c360d80, 0x5b2d8b60, 0x51288a20,
    0x8d4691a0, 0x1b0d8360, 0xaf5795e0, 0x92491240, 0xbb5d9760, 0xdd6e9ba0,
    0xbc5e1780, 0x7f3f8fe0, 0x11088220, 0xd96c9b20, 0x5c2e0b80, 0x41208820,
    0x1f0f83e0, 0x10080200, 0x5a2d0b40, 0xd86c1b00, 0xa050140, 0xc1609820,
    0x31188620, 0x88441100, 0xa55294a0, 0xcd6699a0, 0x7b3d8f60, 0xbd5e97a0,
    0x2d1685a0, 0x743a0e80, 0xd0681a00, 0x12090240, 0xb85c1700, 0xe5729ca0,
    0xb45a1680, 0xb0581600, 0x89449120, 0x69348d20, 0x974b92e0, 0x4a250940,
    0xc060180, 0x964b12c0, 0x773b8ee0, 0x7e3f0fc0, 0x65328ca0, 0xb95c9720,
    0xf1789e20, 0x9048120, 0xc56298a0, 0x6e370dc0, 0xc66318c0, 0x84421080,
    0x180c0300, 0xf0781e00, 0x7d3e8fa0, 0xec761d80, 0x3a1d0740, 0xdc6e1b80,
    0x4d2689a0, 0x20100400, 0x793c8f20, 0xee771dc0, 0x5f2f8be0, 0x3e1f07c0,
    0xd76b9ae0, 0xcb659960, 0x391c8720, 0x48240900
};
//用于密钥扩展优化的S盒1
static const unsigned int SS_Box1[256] = {
    0xc0d66b1a, 0x904812, 0x20e9749d, 0xc0fe7f1f, 0x80cc6619, 0x20e1709c,
    0xa03d1e87, 0xe0b75b96, 0xc0160b02, 0xc0b65b16, 0x80140a02, 0x40c26118,
    0x281405, 0x60fb7d9f, 0x802c1605, 0xa0050280, 0x602b1585, 0xe067338c,
    0x409a4d13, 0xc0763b0e, 0x402a1505, 0xc0be5f17, 0x80040200, 0x60c36198,
    0x40aa5515, 0x80442208, 0x60130982, 0xc0261304, 0x20492489, 0xc0864310,
    0xc0060300, 0x20994c93, 0x809c4e13, 0x40422108, 0x50280a, 0x80f47a1e,
    0x20914892, 0xe0ef779d, 0x984c13, 0x407a3d0f, 0x60331986, 0x80542a0a,
    0x600b0581, 0x60432188, 0xa0ed769d, 0xe0cf6799, 0x80ac5615, 0x4062310c,
    0x80e4721c, 0x60b35996, 0x801c0e03, 0x20a95495, 0x20c96499, 0x80401,
    0xe8741d, 0xa0954a92, 0x804010, 0xe0df6f9b, 0x80944a12, 0x40fa7d1f,
    0xa0753a8e, 0xe08f4791, 0xe03f1f87, 0xc0a65314, 0xe0472388, 0xe0070380,
    0xe0a75394, 0x80fc7e1f, 0x60f3799e, 0x6073398e, 0xe0170b82, 0x40ba5d17,
    0x60834190, 0x20592c8b, 0x803c1e07, 0x20190c83, 0xc0e6731c, 0xa0854290,
    0xe04f2789, 0xa85415, 0x68340d, 0x606b358d, 0x20814090, 0x40b25916,
    0x2071388e, 0x8064320c, 0x40da6d1b, 0x608b4591, 0xf87c1f, 0x60eb759d,
    0xe00f0781, 0x604b2589, 0x70380e, 0xc0562b0a, 0xa09d4e93, 0xa0351a86,
    0xc01e0f03, 0x80241204, 0xc00e0701, 0xc05e2f0b, 0x6063318c, 0x582c0b,
    0x20d1689a, 0x40a25114, 0xa0251284, 0x40221104, 0x807c3e0f, 0x603b1d87,
    0x20010080, 0x20211084, 0x783c0f, 0xe0874390, 0x80d46a1a, 0x0,
    0xc0462308, 0xe0572b8a, 0xe09f4f93, 0x60d3699a, 0xe0271384, 0x4052290a,
    0x804c2609, 0xc0361b06, 0x40020100, 0xe0e7739c, 0xa05014, 0x80c46218,
    0xc86419, 0xc09e4f13, 0x40ea751d, 0xe0bf5f97, 0x408a4511, 0x40d2691a,
    0x402008, 0xe0c76398, 0x381c07, 0xa0b55a96, 0x60a35194, 0xe0f77b9e,
    0x40f2791e, 0xc0ce6719, 0x20f97c9f, 0x2061308c, 0xa0150a82, 0x20a15094,
    0xe0701c, 0xc0ae5715, 0xa05d2e8b, 0x80a45214, 0x609b4d93, 0x80341a06,
    0x401a0d03, 0xa0552a8a, 0xa0ad5695, 0x60934992, 0x40321906, 0x301806,
    0xa0f57a9e, 0x808c4611, 0x20b15896, 0x60e3719c, 0xa01d0e83, 0xc0f67b1e,
    0x40e2711c, 0xc02e1705, 0x40824110, 0xc066330c, 0x40ca6519, 0x60300c,
    0xc06018, 0x20291485, 0x60231184, 0x60ab5595, 0xa00d0681, 0x6053298a,
    0xc04e2709, 0xe06f378d, 0xa0d56a9a, 0x60db6d9b, 0xe0371b86, 0xa0452288,
    0xc0de6f1b, 0xa0fd7e9f, 0xc08e4711, 0xe02f1785, 0x60030180, 0xe0ff7f9f,
    0x406a350d, 0x4072390e, 0xa06d368d, 0x806c360d, 0x605b2d8b, 0x2051288a,
    0xa08d4691, 0x601b0d83, 0xe0af5795, 0x40924912, 0x60bb5d97, 0xa0dd6e9b,
    0x80bc5e17, 0xe07f3f8f, 0x20110882, 0x20d96c9b, 0x805c2e0b, 0x20412088,
    0xe01f0f83, 0x100802, 0x405a2d0b, 0xd86c1b, 0x400a0501, 0x20c16098,
    0x20311886, 0x884411, 0xa0a55294, 0xa0cd6699, 0x607b3d8f, 0xa0bd5e97,
    0xa02d1685, 0x80743a0e, 0xd0681a, 0x40120902, 0xb85c17, 0xa0e5729c,
    0x80b45a16, 0xb05816, 0x20894491, 0x2069348d, 0xe0974b92, 0x404a2509,
    0x800c0601, 0xc0964b12, 0xe0773b8e, 0xc07e3f0f, 0xa065328c, 0x20b95c97,
    0x20f1789e, 0x20090481, 0xa0c56298, 0xc06e370d, 0xc0c66318, 0x80844210,
    0x180c03, 0xf0781e, 0xa07d3e8f, 0x80ec761d, 0x403a1d07, 0x80dc6e1b,
    0xa04d2689, 0x201004, 0x20793c8f, 0xc0ee771d, 0xe05f2f8b, 0xc03e1f07,
    0xe0d76b9a, 0x60cb6599, 0x20391c87, 0x482409
};
//用于密钥扩展优化的S盒2
static const unsigned int SS_Box2[256] = {
    0x1ac0d66b, 0x12009048, 0x9d20e974, 0x1fc0fe7f, 0x1980cc66, 0x9c20e170,
    0x87a03d1e, 0x96e0b75b, 0x2c0160b, 0x16c0b65b, 0x280140a, 0x1840c261,
    0x5002814, 0x9f60fb7d, 0x5802c16, 0x80a00502, 0x85602b15, 0x8ce06733,
    0x13409a4d, 0xec0763b, 0x5402a15, 0x17c0be5f, 0x800402, 0x9860c361,
    0x1540aa55, 0x8804422, 0x82601309, 0x4c02613, 0x89204924, 0x10c08643,
    0xc00603, 0x9320994c, 0x13809c4e, 0x8404221, 0xa005028, 0x1e80f47a,
    0x92209148, 0x9de0ef77, 0x1300984c, 0xf407a3d, 0x86603319, 0xa80542a,
    0x81600b05, 0x88604321, 0x9da0ed76, 0x99e0cf67, 0x1580ac56, 0xc406231,
    0x1c80e472, 0x9660b359, 0x3801c0e, 0x9520a954, 0x9920c964, 0x1000804,
    0x1d00e874, 0x92a0954a, 0x10008040, 0x9be0df6f, 0x1280944a, 0x1f40fa7d,
    0x8ea0753a, 0x91e08f47, 0x87e03f1f, 0x14c0a653, 0x88e04723, 0x80e00703,
    0x94e0a753, 0x1f80fc7e, 0x9e60f379, 0x8e607339, 0x82e0170b, 0x1740ba5d,
    0x90608341, 0x8b20592c, 0x7803c1e, 0x8320190c, 0x1cc0e673, 0x90a08542,
    0x89e04f27, 0x1500a854, 0xd006834, 0x8d606b35, 0x90208140, 0x1640b259,
    0x8e207138, 0xc806432, 0x1b40da6d, 0x91608b45, 0x1f00f87c, 0x9d60eb75,
    0x81e00f07, 0x89604b25, 0xe007038, 0xac0562b, 0x93a09d4e, 0x86a0351a,
    0x3c01e0f, 0x4802412, 0x1c00e07, 0xbc05e2f, 0x8c606331, 0xb00582c,
    0x9a20d168, 0x1440a251, 0x84a02512, 0x4402211, 0xf807c3e, 0x87603b1d,
    0x80200100, 0x84202110, 0xf00783c, 0x90e08743, 0x1a80d46a, 0x0,
    0x8c04623, 0x8ae0572b, 0x93e09f4f, 0x9a60d369, 0x84e02713, 0xa405229,
    0x9804c26, 0x6c0361b, 0x400201, 0x9ce0e773, 0x1400a050, 0x1880c462,
    0x1900c864, 0x13c09e4f, 0x1d40ea75, 0x97e0bf5f, 0x11408a45, 0x1a40d269,
    0x8004020, 0x98e0c763, 0x700381c, 0x96a0b55a, 0x9460a351, 0x9ee0f77b,
    0x1e40f279, 0x19c0ce67, 0x9f20f97c, 0x8c206130, 0x82a0150a, 0x9420a150,
    0x1c00e070, 0x15c0ae57, 0x8ba05d2e, 0x1480a452, 0x93609b4d, 0x680341a,
    0x3401a0d, 0x8aa0552a, 0x95a0ad56, 0x92609349, 0x6403219, 0x6003018,
    0x9ea0f57a, 0x11808c46, 0x9620b158, 0x9c60e371, 0x83a01d0e, 0x1ec0f67b,
    0x1c40e271, 0x5c02e17, 0x10408241, 0xcc06633, 0x1940ca65, 0xc006030,
    0x1800c060, 0x85202914, 0x84602311, 0x9560ab55, 0x81a00d06, 0x8a605329,
    0x9c04e27, 0x8de06f37, 0x9aa0d56a, 0x9b60db6d, 0x86e0371b, 0x88a04522,
    0x1bc0de6f, 0x9fa0fd7e, 0x11c08e47, 0x85e02f17, 0x80600301, 0x9fe0ff7f,
    0xd406a35, 0xe407239, 0x8da06d36, 0xd806c36, 0x8b605b2d, 0x8a205128,
    0x91a08d46, 0x83601b0d, 0x95e0af57, 0x12409249, 0x9760bb5d, 0x9ba0dd6e,
    0x1780bc5e, 0x8fe07f3f, 0x82201108, 0x9b20d96c, 0xb805c2e, 0x88204120,
    0x83e01f0f, 0x2001008, 0xb405a2d, 0x1b00d86c, 0x1400a05, 0x9820c160,
    0x86203118, 0x11008844, 0x94a0a552, 0x99a0cd66, 0x8f607b3d, 0x97a0bd5e,
    0x85a02d16, 0xe80743a, 0x1a00d068, 0x2401209, 0x1700b85c, 0x9ca0e572,
    0x1680b45a, 0x1600b058, 0x91208944, 0x8d206934, 0x92e0974b, 0x9404a25,
    0x1800c06, 0x12c0964b, 0x8ee0773b, 0xfc07e3f, 0x8ca06532, 0x9720b95c,
    0x9e20f178, 0x81200904, 0x98a0c562, 0xdc06e37, 0x18c0c663, 0x10808442,
    0x300180c, 0x1e00f078, 0x8fa07d3e, 0x1d80ec76, 0x7403a1d, 0x1b80dc6e,
    0x89a04d26, 0x4002010, 0x8f20793c, 0x1dc0ee77, 0x8be05f2f, 0x7c03e1f,
    0x9ae0d76b, 0x9960cb65, 0x8720391c, 0x9004824
};
//用于密钥扩展优化的S盒3
static const unsigned int SS_Box3[256] = {
    0x6b1ac0d6, 0x48120090, 0x749d20e9, 0x7f1fc0fe, 0x661980cc, 0x709c20e1,
    0x1e87a03d, 0x5b96e0b7, 0xb02c016, 0x5b16c0b6, 0xa028014, 0x611840c2,
    0x14050028, 0x7d9f60fb, 0x1605802c, 0x280a005, 0x1585602b, 0x338ce067,
    0x4d13409a, 0x3b0ec076, 0x1505402a, 0x5f17c0be, 0x2008004, 0x619860c3,
    0x551540aa, 0x22088044, 0x9826013, 0x1304c026, 0x24892049, 0x4310c086,
    0x300c006, 0x4c932099, 0x4e13809c, 0x21084042, 0x280a0050, 0x7a1e80f4,
    0x48922091, 0x779de0ef, 0x4c130098, 0x3d0f407a, 0x19866033, 0x2a0a8054,
    0x581600b, 0x21886043, 0x769da0ed, 0x6799e0cf, 0x561580ac, 0x310c4062,
    0x721c80e4, 0x599660b3, 0xe03801c, 0x549520a9, 0x649920c9, 0x4010008,
    0x741d00e8, 0x4a92a095, 0x40100080, 0x6f9be0df, 0x4a128094, 0x7d1f40fa,
    0x3a8ea075, 0x4791e08f, 0x1f87e03f, 0x5314c0a6, 0x2388e047, 0x380e007,
    0x5394e0a7, 0x7e1f80fc, 0x799e60f3, 0x398e6073, 0xb82e017, 0x5d1740ba,
    0x41906083, 0x2c8b2059, 0x1e07803c, 0xc832019, 0x731cc0e6, 0x4290a085,
    0x2789e04f, 0x541500a8, 0x340d0068, 0x358d606b, 0x40902081, 0x591640b2,
    0x388e2071, 0x320c8064, 0x6d1b40da, 0x4591608b, 0x7c1f00f8, 0x759d60eb,
    0x781e00f, 0x2589604b, 0x380e0070, 0x2b0ac056, 0x4e93a09d, 0x1a86a035,
    0xf03c01e, 0x12048024, 0x701c00e, 0x2f0bc05e, 0x318c6063, 0x2c0b0058,
    0x689a20d1, 0x511440a2, 0x1284a025, 0x11044022, 0x3e0f807c, 0x1d87603b,
    0x802001, 0x10842021, 0x3c0f0078, 0x4390e087, 0x6a1a80d4, 0x0,
    0x2308c046, 0x2b8ae057, 0x4f93e09f, 0x699a60d3, 0x1384e027, 0x290a4052,
    0x2609804c, 0x1b06c036, 0x1004002, 0x739ce0e7, 0x501400a0, 0x621880c4,
    0x641900c8, 0x4f13c09e, 0x751d40ea, 0x5f97e0bf, 0x4511408a, 0x691a40d2,
    0x20080040, 0x6398e0c7, 0x1c070038, 0x5a96a0b5, 0x519460a3, 0x7b9ee0f7,
    0x791e40f2, 0x6719c0ce, 0x7c9f20f9, 0x308c2061, 0xa82a015, 0x509420a1,
    0x701c00e0, 0x5715c0ae, 0x2e8ba05d, 0x521480a4, 0x4d93609b, 0x1a068034,
    0xd03401a, 0x2a8aa055, 0x5695a0ad, 0x49926093, 0x19064032, 0x18060030,
    0x7a9ea0f5, 0x4611808c, 0x589620b1, 0x719c60e3, 0xe83a01d, 0x7b1ec0f6,
    0x711c40e2, 0x1705c02e, 0x41104082, 0x330cc066, 0x651940ca, 0x300c0060,
    0x601800c0, 0x14852029, 0x11846023, 0x559560ab, 0x681a00d, 0x298a6053,
    0x2709c04e, 0x378de06f, 0x6a9aa0d5, 0x6d9b60db, 0x1b86e037, 0x2288a045,
    0x6f1bc0de, 0x7e9fa0fd, 0x4711c08e, 0x1785e02f, 0x1806003, 0x7f9fe0ff,
    0x350d406a, 0x390e4072, 0x368da06d, 0x360d806c, 0x2d8b605b, 0x288a2051,
    0x4691a08d, 0xd83601b, 0x5795e0af, 0x49124092, 0x5d9760bb, 0x6e9ba0dd,
    0x5e1780bc, 0x3f8fe07f, 0x8822011, 0x6c9b20d9, 0x2e0b805c, 0x20882041,
    0xf83e01f, 0x8020010, 0x2d0b405a, 0x6c1b00d8, 0x501400a, 0x609820c1,
    0x18862031, 0x44110088, 0x5294a0a5, 0x6699a0cd, 0x3d8f607b, 0x5e97a0bd,
    0x1685a02d, 0x3a0e8074, 0x681a00d0, 0x9024012, 0x5c1700b8, 0x729ca0e5,
    0x5a1680b4, 0x581600b0, 0x44912089, 0x348d2069, 0x4b92e097, 0x2509404a,
    0x601800c, 0x4b12c096, 0x3b8ee077, 0x3f0fc07e, 0x328ca065, 0x5c9720b9,
    0x789e20f1, 0x4812009, 0x6298a0c5, 0x370dc06e, 0x6318c0c6, 0x42108084,
    0xc030018, 0x781e00f0, 0x3e8fa07d, 0x761d80ec, 0x1d07403a, 0x6e1b80dc,
    0x2689a04d, 0x10040020, 0x3c8f2079, 0x771dc0ee, 0x2f8be05f, 0x1f07c03e,
    0x6b9ae0d7, 0x659960cb, 0x1c872039, 0x24090048
};
//用于密钥扩展的系统参数
static const uint32_t FK[4] = {
    0xa3b1bac6,0x56aa3350,
    0x677d9197,0xb27022dc
};
//用于密钥扩展的固定参数
static const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

//定义uint32_t转化为字节
#define Ulong_to_Byte(Ulong,Uchar_vector,sta_index)					\
{											\
	(Uchar_vector)[(sta_index)    ] = (unsigned char)((Ulong) >> 24);		\
	(Uchar_vector)[(sta_index) + 1] = (unsigned char)((Ulong) >> 16);		\
	(Uchar_vector)[(sta_index) + 2] = (unsigned char)((Ulong) >> 8 );		\
	(Uchar_vector)[(sta_index) + 3] = (unsigned char)((Ulong)      );		\
}

//定义字节转化为uint32_t
#define Byte_to_Ulong(Ulong,Uchar_vector,sta_index)					\
{											\
	(Ulong) = ((uint32_t)(Uchar_vector)[(sta_index)]  )		   		\
	| ((uint32_t)(Uchar_vector)[(sta_index)+ 1] << 8  )				\
	| ((uint32_t)(Uchar_vector)[(sta_index)+ 2] << 16 )				\
	| ((uint32_t)(Uchar_vector)[(sta_index)+ 3] << 24 );	        		\
}

//循环左移
#define Shift_left(n,step) (((n) << (step)) | ((n) >> (32 - step)))


//函数定义
//加密/解密
void SM4(uint8_t plaintex[16], uint8_t ciphertext[16], uint32_t RK[32], bool decryption = 0)
{
    uint32_t X[4];
    uint32_t X_temp;
    uint32_t B;
    Byte_to_Ulong(X[0], plaintex, 12)
        Byte_to_Ulong(X[1], plaintex, 8)
        Byte_to_Ulong(X[2], plaintex, 4)
        Byte_to_Ulong(X[3], plaintex, 0)

        for (int i = 0; i < 32; i++)
        {

            X_temp = (decryption == 0) ? RK[i] : RK[31 - i];
            X_temp = X[1] ^ X[2] ^ X[3] ^ X_temp;
            B = X[0];
            B ^= S_Box0[(X_temp >> 24) & 0xff];
            B ^= S_Box1[(X_temp >> 16) & 0xff];
            B ^= S_Box2[(X_temp >> 8) & 0xff];
            B ^= S_Box3[(X_temp >> 0) & 0xff];

            X[0] = X[1];
            X[1] = X[2];
            X[2] = X[3];
            X[3] = B;
        }
    Ulong_to_Byte(X[0], ciphertext, 12)
        Ulong_to_Byte(X[1], ciphertext, 8)
        Ulong_to_Byte(X[2], ciphertext, 4)
        Ulong_to_Byte(X[3], ciphertext, 0)
}

//密钥拓展F函数
static uint32_t SM4_F_key(uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3, uint32_t ck)
{
    uint8_t b[4];
    uint32_t res;
    uint32_t Ulong = K1 ^ K2 ^ K3 ^ ck;
    Ulong_to_Byte(Ulong, b, 0)
        b[0] = S_Box[b[0]];
    b[1] = S_Box[b[1]];
    b[2] = S_Box[b[2]];
    b[3] = S_Box[b[3]];
    res = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | ((uint32_t)b[3]);
    return (K0 ^ res ^ (Shift_left(res, 13)) ^ (Shift_left(res, 23)));
}

//不查表优化密钥拓展
void SM4_generate_key_v1(uint32_t RK[32], uint8_t key[16])
{
    uint32_t MK[4], K[36];
    Byte_to_Ulong(MK[0], key, 12)
        Byte_to_Ulong(MK[1], key, 8)
        Byte_to_Ulong(MK[2], key, 4)
        Byte_to_Ulong(MK[3], key, 0)
        K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++)
    {
        K[i + 4] = SM4_F_key(K[i], K[i + 1], K[i + 2], K[i + 3], CK[i]);
        RK[i] = K[i + 4];
    }
}

//查表（“S盒”）优化密钥拓展
void SM4_generate_key_v2(uint32_t RK[32], uint8_t key[16])
{
    uint32_t MK[4], K[4], K_temp, temp;
    Byte_to_Ulong(MK[0], key, 12)
        Byte_to_Ulong(MK[1], key, 8)
        Byte_to_Ulong(MK[2], key, 4)
        Byte_to_Ulong(MK[3], key, 0)
        K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++)
    {
        K_temp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        temp = K[0];
        temp ^= SS_Box0[(K_temp >> 24) & 0xff];
        temp ^= SS_Box1[(K_temp >> 16) & 0xff];
        temp ^= SS_Box2[(K_temp >> 8) & 0xff];
        temp ^= SS_Box3[(K_temp >> 0) & 0xff];

        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = temp;
        RK[i] = temp;
    }
}

//SM4加密、SM4解密、密钥扩展优化
int main()
{
    clock_t start_time, end_time;//时间

    uint8_t plaintext[16] = { 0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE,0xEF,0xCD,0xAB,0x89,0x67,0x45,0x23,0x01 };//明文
    uint8_t ciphertext[16];                                                                                    //密文
    uint8_t key_seed[16] = { 0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE,0xEF,0xCD,0xAB,0x89,0x67,0x45,0x23,0x01 };//密钥
    uint32_t RK[32];                                                                                           //密钥扩展

    //生成轮密钥
    SM4_generate_key_v1(RK, key_seed);

    //SM4加密
    SM4(plaintext, ciphertext, RK, 0);
    cout << "加密结果:" << endl;
    for (int i = 0; i < 16; i++)
        cout << "0x" << hex << setw(2) << setfill('0') << (int)ciphertext[i] << "\t";

    //SM4解密
    cout << endl << "解密结果:" << endl;
    SM4(plaintext, ciphertext, RK, 1);
    for (int i = 0; i < 16; i++)
        cout << hex << "0x" << (int)(plaintext[i] >> 4) << (int)(plaintext[i] & 0xf) << "\t";
    cout << "\n正确的结果:" << endl;
    for (int i = 0; i < 16; i++)
        cout << "0x" << hex << setw(2) << setfill('0') << (int)plaintext[i] << "\t";


    //使用查表优化的SM4加密
    start_time = clock();
    for (int i = 0; i < pow(10, 6); i++)
    {
        SM4_generate_key_v2(RK, key_seed);
        SM4(plaintext, ciphertext, RK, 0);
    }
    end_time = clock();
    cout << endl << "\n使用查表优化:\nSM4加密pow(10,6)次总时间为" << (double)(end_time - start_time) / CLOCKS_PER_SEC << "s";

    //不使用查表优化的SM4加密
    start_time = clock();
    for (int i = 0; i < pow(10, 6); i++)
    {
        SM4_generate_key_v1(RK, key_seed);
        SM4(plaintext, ciphertext, RK, 0);
    }
    end_time = clock();
    cout << endl << "\n不使用查表优化:\nSM4加密pow(10,6)次总时间为" << (double)(end_time - start_time) / CLOCKS_PER_SEC << "s";

    cout << endl;

    return 0;
}
