#include <net/genetlink.h>
#include "ecryptfs_kernel.h"
#include "netlink.h"

//#define LOG_SIZE 4096
static const struct nla_policy policy[__CSFSNETLINK_A_MAX+1] = {
	[CSFSNETLINK_A_USER_ST] = { .type=NLA_STRING, .len = (sizeof(u64)*4), },
	[CSFSNETLINK_A_APP_CFG] = { .type=NLA_STRING, .len = (sizeof(struct credit_app) * MAX_EXT_ENTRYS * 2)},
	[CSFSNETLINK_A_ENC_KEY] = { .type=NLA_STRING, .len = (ECRYPTFS_DEFAULT_KEY_BYTES*2*4), },
	[CSFSNETLINK_A_UNDO_ENT_FILE] = { .type=NLA_STRING, .len = PATH_MAX, }
};

static int do_user_status(struct sk_buff *skb, struct genl_info *info);
static int do_app_config(struct sk_buff *skb, struct genl_info *info);
static int do_enterprise_enc(struct sk_buff *skb, struct genl_info *info);
static const struct genl_ops ops[] = {
	{
		.flags	= 0,
		.policy = policy,
		.cmd	= CSFSNETLINK_C_SET_USER_STAT,
		.doit	= do_user_status,
	},
	{
		.flags	= 0,
		.policy = policy,
		.cmd	= CSFSNETLINK_C_SET_APP_CFG,
		.doit	= do_app_config,
	},
	{
		.flags	= 0,
		.policy = policy,
		.cmd	= CSFSNETLINK_C_SET_ENC_SUITE,
		.doit	= do_enterprise_enc,
	}
};

static struct genl_family family = {
	.name		= CSCRYPTFS_NETLINK_NAME,
	.version	= CSCRYPTFS_NETLINK_VERSION,
	.ops		= ops,
	.n_ops		= ARRAY_SIZE(ops),
	.module		= THIS_MODULE,
	.maxattr	= __CSFSNETLINK_A_MAX,
	.hdrsize	= 0,
};

extern struct net init_net;

int send_netlink_msg(void *buf, int size, int portid, int seq, int cmd, int attr)
{
	struct sk_buff *skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) return -ENOMEM;
	
	void *msg_head = genlmsg_put(skb, 0, seq, &family, 0, cmd);
	if (!msg_head) {
		kfree_skb(skb);
		return -ENOMEM;
	}
	nla_put(skb, attr, size, buf);
	genlmsg_end(skb, msg_head);
	return genlmsg_unicast(&init_net, skb, portid);
}
static int do_user_status(struct sk_buff *skb, struct genl_info *info)
{
    u64 enterprise_id = 0;
    u64 user_id = 0;
    u64 device_id = 0;
	if (!info) return 0;
	struct nlattr *na = info->attrs[CSFSNETLINK_A_USER_ST];
	if (!na) return 0;
	char *data = nla_data(na);
	if (!data) return 0;
    if (data[0] != '0') {       //example:  1:123,2:124,3:456
		char * ptr = kstrdup(data, GFP_KERNEL);
        char *cur = ptr;
        char *token, *pos;
        while((token = strsep(&cur, ","))) {
            if (token[0] == 'e'){
                pos = &token[2];
                enterprise_id = (u64)simple_strtoll(pos, &pos, 0);
            } else if (token[0] == 'u') {
                pos = &token[2];
                user_id = (u64)simple_strtoll(pos, &pos, 0);
            } else if (token[0] == 'd') {
                pos = &token[2];
                device_id = (u64)simple_strtoll(pos, &pos, 0);
            }
        } 
		kfree(ptr);
        ecryptfs_printk(KERN_INFO, 
            "register user login, enterprise_id:%llu, user_id:%llu, device_id:%llu\n",
            enterprise_id, user_id, device_id);
		enterprise_stat.login = 1;
		enterprise_stat.user_id = user_id;
		enterprise_stat.device_id = device_id;		
		enterprise_stat.enterprise_id = enterprise_id;
    } else {
		enterprise_stat.login = 0;
        ecryptfs_printk(KERN_INFO, "register user logout\n");
    }
	
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat_tmp;
	mutex_lock(&mount_crypt_stat_list_mutex);
	list_for_each_entry(mount_crypt_stat_tmp, &mount_crypt_stat_list, mount_crypt_stat_list) {
		mutex_lock(&mount_crypt_stat_tmp->mux);
		encryptfs_enterprise_parse(mount_crypt_stat_tmp);
		mutex_unlock(&mount_crypt_stat_tmp->mux);
	}	
	mutex_unlock(&mount_crypt_stat_list_mutex);
	encryptfs_enterprise_save();
	return 0;
}

static int do_app_config(struct sk_buff *skb, struct genl_info *info)
{
	char *ext = NULL, *comms = NULL;
	if (!info) return 0;
	struct nlattr *na = info->attrs[CSFSNETLINK_A_APP_CFG];
	if (!na) return 0;
	char *data = nla_data(na);
	if (!data) return 0;
	char * ptr = kstrdup(data, GFP_KERNEL);
	char *record, *records = ptr;
	int idx = 0;
	ecryptfs_printk(KERN_INFO,  "app configs records:%s\n", ptr);
	while((record = strsep(&records, ";")) && idx < MAX_EXT_ENTRYS) {
		char *cur = strchr(record, ':');
		ecryptfs_printk(KERN_INFO,  "record:%s\n", record);
		if (cur) {
			*cur = '\0';
			ext = record;
			comms = cur + 1;
			ecryptfs_printk(KERN_INFO,  "register trusted apps:%s\n", comms);
			memset(&enterprise_stat.credit_entrys[idx], 0, sizeof(enterprise_stat.credit_entrys[idx]));
			strcpy(enterprise_stat.credit_entrys[idx].ext, ext);
			int j = 0;
			char *token;
			while ((token = strsep(&comms, ",")) && j < EXT_MAX_CREDIT_NUM) {
				if (strlen(token) < TASK_COMM_LEN) {
					strcpy(enterprise_stat.credit_entrys[idx].comms[j++], token);
				}
			}
			enterprise_stat.entrys_num++;
			idx++;
		}
	}
	if (idx > 0) {
		struct ecryptfs_mount_crypt_stat *mount_crypt_stat_tmp;
		mutex_lock(&mount_crypt_stat_list_mutex);
		list_for_each_entry(mount_crypt_stat_tmp, &mount_crypt_stat_list, mount_crypt_stat_list) {
			mutex_lock(&mount_crypt_stat_tmp->mux);
			encryptfs_enterprise_parse(mount_crypt_stat_tmp);
			mutex_unlock(&mount_crypt_stat_tmp->mux);
		}	
		mutex_unlock(&mount_crypt_stat_list_mutex);
		encryptfs_enterprise_save();
	}

	kfree(ptr);
	return 0;
}

static int do_enterprise_enc(struct sk_buff *skb, struct genl_info *info) 
{
	if (!info) return 0;
	struct nlattr *na = info->attrs[CSFSNETLINK_A_ENC_KEY];
	if (!na) return 0;
	char *data = nla_data(na);
	if (!data) return 0;
	//printk("register test data:%s\n", data);
	char * ptr = kstrdup(data, GFP_KERNEL);
	char *cur = ptr;
	char *token, *pos;
	while((token = strsep(&cur, ","))) {
		if (token[0] == 'k'){			// kek
			pos = &token[2];
			
		} else if (token[0] == 'v') {	// key cipher
			pos = &token[2];
			ecryptfs_from_hex(CSCRYPTFS_TEST_FEK, pos, ECRYPTFS_DEFAULT_KEY_BYTES);
			memcpy(enterprise_stat.key, CSCRYPTFS_TEST_FEK, ECRYPTFS_DEFAULT_KEY_BYTES);
			ecryptfs_printk(KERN_DEBUG, "key :%s\n", pos);
		} else if (token[0] == 't') {	// key plain for test
			pos = &token[2];
		} else {
			ecryptfs_printk(KERN_ERR, "unknow id type %c\n", token[0]);
		}
	} 
	encryptfs_enterprise_save();
	kfree(ptr);
	// ecryptfs_printk(KERN_INFO, 
	//     "register user login, enterprise_id:%llu, user_id:%llu, device_id:%llu\n",
	//     enterprise_id, user_id, device_id);
	
	return 0;
}

int cscryptfs_netlink_init(void)
{
	int rc = genl_register_family(&family);
	if (rc==0){
		printk("csnetlink is loaded.\n");
		return 0;
	}else{
		printk("csnetlink isn't loaded.\n");
		return rc;
	}
}

void cscryptfs_netlink_exit(void)
{
	genl_unregister_family(&family);
}
