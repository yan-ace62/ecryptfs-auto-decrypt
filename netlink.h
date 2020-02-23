#ifndef CSCRYPTFS_NETLINK_H
#define CSCRYPTFS_NETLINK_H

#define CSCRYPTFS_NETLINK_NAME "CSFSNETLINK"
#define CSCRYPTFS_NETLINK_VERSION 1
//#define REPORT_PORT 1
#define ENT_FILE_REPORT_PORT 2

enum {
    CSFSNETLINK_A_UNSPEC = 0,
    CSFSNETLINK_A_USER_ST,
    CSFSNETLINK_A_APP_CFG,
    CSFSNETLINK_A_ENC_KEY,
    CSFSNETLINK_A_UNDO_ENT_FILE = 7,
    CSFSNETLINK_A_ENT_FILE_EVENT = 8,
    __CSFSNETLINK_A_MAX,
};

enum {
    CSFSNETLINK_C_UNSPEC = 0,
    CSFSNETLINK_C_SET_USER_STAT,
    CSFSNETLINK_C_SET_APP_CFG,
    CSFSNETLINK_C_SET_ENC_SUITE,
    CSFSNETLINK_C_UNDO_ENT_FILE = 7,
    CSFSNETLINK_C_REPORT_ENT_FILE_EVENT = 8,
    __CSFSNETLINK_C_MAX,
};
#endif

//上报企业文件操作例如 编辑
// "02|/sd/xx/xx.txt.csx"
// 重命名
// "512|/s/xx/xx.txt.csx"
//报告待处理的企业文件 "0|/sdf/x/x/dd.doc"              //确认需要加密
//                  "1|/sss/d/xx/dd.xlsx"           //待确认是否企业文件需要加密

// 1.通知用户登录登录命令: CSFSNETLINK_C_SET_USER_STAT,  数据属性:CSFSNETLINK_A_USER_ST
//  数据示例 登录 "e:123,u:34,d:6" 传输登录后的企业ID enterprise_id， 用户ID user_id， 设备ID device_id
//          登出 "0"
// 2.注册指定文档类型的可信应用命令: CSFSNETLINK_C_SET_APP_CFG , 数据属性:CSFSNETLINK_A_APP_CFG
//  数据示例    "doc:opendoc,ls,cat",  文件类型:应用名称1,应用名称2,...
//
// 3.注册企业加密信息命令命令CSFSNETLINK_C_SET_ENC_SUITE, 数据属性:CSFSNETLINK_A_ENC_KEY
//    示例  "k:密钥保护密钥hex,v:密钥密文hex,t:测试用的密钥明文hex"