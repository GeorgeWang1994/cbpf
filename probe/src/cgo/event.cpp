#include "event.h"
#include "scap_open_exception.h"
#include "sinsp_capture_interrupt_exception.h"
#include <iostream>
#include <cstdlib>

static sinsp *inspector = nullptr;

int cnt = 0;
// 事件
map<string, ppm_event_type> m_events;
// 类别
map<string, Category> m_categories;
int16_t event_filters[1024][16];

// 初始化标签
void init_sub_label()
{
	for(auto e : kindling_to_sysdig)
	{
		m_events[e.event_name] = e.event_type;
	}
	for(auto c : category_map)
	{
		m_categories[c.cateogry_name] = c.category_value;
	}
	for(int i = 0; i < 1024; i++)
	{
		for(int j = 0; j < 16; j++)
		{
			event_filters[i][j] = 0;
		}
	}
}

// 
void sub_event(char *eventName, char *category)
{
	cout << "sub event name:" << eventName << "  &&  category:" << category << endl;
	auto it_type = m_events.find(eventName);
	if(it_type != m_events.end())
	{
		if(category == nullptr || category[0] == '\0')
		{
			for(int j = 0; j < 16; j++)
			{
				event_filters[it_type->second][j] = 1;
			}
		}
		else
		{
			auto it_category = m_categories.find(category);
			if(it_category != m_categories.end())
			{
				event_filters[it_type->second][it_category->second] = 1;
			}
		}
	}
}

void init_probe()
{
	bool bpf = false;
	string bpf_probe;
	inspector = new sinsp();
	init_sub_label();
	string output_format;
	output_format = "*%evt.num %evt.outputtime %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";
	try
	{
		inspector = new sinsp();
		inspector->set_hostname_and_port_resolution_mode(false);
		inspector->set_snaplen(80);

		inspector->suppress_events_comm("containerd");
		inspector->suppress_events_comm("dockerd");
		inspector->suppress_events_comm("containerd-shim");
		inspector->suppress_events_comm("kindling-collector");
		inspector->suppress_events_comm("sshd");
		sinsp_evt_formatter formatter(inspector, output_format);
		const char *probe = scap_get_bpf_probe_from_env();
		if(probe)
		{
			bpf = true;
			bpf_probe = probe;
		}

		bool open_success = true;

		try
		{
			inspector->open("");
			inspector->clear_eventmask();
			inspector->set_eventmask(PPME_SYSCALL_WRITEV_X);
			inspector->set_eventmask(PPME_SYSCALL_WRITEV_X - 1);
			inspector->set_eventmask(PPME_SYSCALL_WRITE_X);
			inspector->set_eventmask(PPME_SYSCALL_WRITE_E);
			inspector->set_eventmask(PPME_SYSCALL_READ_X);
			inspector->set_eventmask(PPME_SYSCALL_READ_E);
		}
		catch(const sinsp_exception &e)
		{
			open_success = false;
			cout << "open failed" << endl;
		}

		//
		// Starting the live capture failed, try to load the driver with
		// modprobe.
		//
		if(!open_success)
		{
			if(bpf)
			{
				if(bpf_probe.empty())
				{
					fprintf(stderr, "Unable to locate the BPF probe\n");
				}
			}

			inspector->open("");
		}
	}
	catch(const exception &e)
	{
		fprintf(stderr, "kindling probe init err: %s", e.what());
	}
}

int getEvent(void **pp_kindling_event)
{
	int32_t res;
	sinsp_evt *ev;
	res = inspector->next(&ev);
	if(res == SCAP_TIMEOUT)
	{
		return -1;
	}
	else if(res != SCAP_SUCCESS)
	{
		return -1;
	}
	if(!inspector->is_debug_enabled() &&
	   ev->get_category() & EC_INTERNAL)
	{
		return -1;
	}
	auto threadInfo = ev->get_thread_info();
	if(threadInfo == nullptr)
	{
		return -1;
	}

	auto category = ev->get_category();
	if(category & EC_IO_BASE)
	{
		auto pres = ev->get_param_value_raw("res");
		if(pres && *(int64_t *)pres->m_val <= 0)
		{
			return -1;
		}
	}

	uint16_t kindling_category = get_kindling_category(ev);
	uint16_t ev_type = ev->get_type();
	if(event_filters[ev_type][kindling_category] == 0)
	{
		return -1;
	}

	kindling_event_t_for_go *p_kindling_event;
	if(nullptr == *pp_kindling_event)
	{
		*pp_kindling_event = (kindling_event_t_for_go *)malloc(sizeof(kindling_event_t_for_go));
		p_kindling_event = (kindling_event_t_for_go *)*pp_kindling_event;

		p_kindling_event->name = (char *)malloc(sizeof(char) * 1024);
		p_kindling_event->context.tinfo.comm = (char *)malloc(sizeof(char) * 256);
		p_kindling_event->context.tinfo.containerId = (char *)malloc(sizeof(char) * 256);
		p_kindling_event->context.fdInfo.filename = (char *)malloc(sizeof(char) * 1024);
		p_kindling_event->context.fdInfo.directory = (char *)malloc(sizeof(char) * 1024);

		for(int i = 0; i < 8; i++)
		{
			p_kindling_event->userAttributes[i].key = (char *)malloc(sizeof(char) * 128);
			p_kindling_event->userAttributes[i].value = (char *)malloc(sizeof(char) * 1024);
		}
	}
	p_kindling_event = (kindling_event_t_for_go *)*pp_kindling_event;

	sinsp_fdinfo_t *fdInfo = ev->get_fd_info();
	p_kindling_event->timestamp = ev->get_ts();
	p_kindling_event->category = kindling_category;
	p_kindling_event->context.tinfo.pid = threadInfo->m_pid;
	p_kindling_event->context.tinfo.tid = threadInfo->m_tid;
	p_kindling_event->context.tinfo.uid = threadInfo->m_uid;
	p_kindling_event->context.tinfo.gid = threadInfo->m_gid;
	p_kindling_event->context.fdInfo.num = ev->get_fd_num();
	if(nullptr != fdInfo)
	{
		p_kindling_event->context.fdInfo.fdType = fdInfo->m_type;

		switch(fdInfo->m_type)
		{
		case SCAP_FD_FILE:
		case SCAP_FD_FILE_V2:
		{

			string name = fdInfo->m_name;
			size_t pos = name.rfind('/');
			if(pos != string::npos)
			{
				if(pos < name.size() - 1)
				{
					string fileName = name.substr(pos + 1, string::npos);
					memcpy(p_kindling_event->context.fdInfo.filename, fileName.data(), fileName.length());
					if(pos != 0)
					{

						name.resize(pos);

						strcpy(p_kindling_event->context.fdInfo.directory, (char *)name.data());
					}
					else
					{
						strcpy(p_kindling_event->context.fdInfo.directory, "/");
					}
				}
			}
			break;
		}
		case SCAP_FD_IPV4_SOCK:
		case SCAP_FD_IPV4_SERVSOCK:
			p_kindling_event->context.fdInfo.protocol = get_protocol(fdInfo->get_l4proto());
			p_kindling_event->context.fdInfo.role = fdInfo->is_role_server();
			p_kindling_event->context.fdInfo.sip = fdInfo->m_sockinfo.m_ipv4info.m_fields.m_sip;
			p_kindling_event->context.fdInfo.dip = fdInfo->m_sockinfo.m_ipv4info.m_fields.m_dip;
			p_kindling_event->context.fdInfo.sport = fdInfo->m_sockinfo.m_ipv4info.m_fields.m_sport;
			p_kindling_event->context.fdInfo.dport = fdInfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
			break;
		case SCAP_FD_UNIX_SOCK:
			p_kindling_event->context.fdInfo.source = fdInfo->m_sockinfo.m_unixinfo.m_fields.m_source;
			p_kindling_event->context.fdInfo.destination = fdInfo->m_sockinfo.m_unixinfo.m_fields.m_dest;
			break;
		default:
			break;
		}
	}

	uint16_t userAttNumber = 0;
	switch(ev->get_type())
	{
	case PPME_TCP_RCV_ESTABLISHED_E:
	case PPME_TCP_CLOSE_E:
	{
		auto pTuple = ev->get_param_value_raw("tuple");
		userAttNumber = setTuple(p_kindling_event, pTuple, userAttNumber);

		auto pRtt = ev->get_param_value_raw("srtt");
		if(pRtt != NULL)
		{
			strcpy(p_kindling_event->userAttributes[userAttNumber].key, "rtt");
			memcpy(p_kindling_event->userAttributes[userAttNumber].value, pRtt->m_val, pRtt->m_len);
			p_kindling_event->userAttributes[userAttNumber].valueType = UINT32;
			p_kindling_event->userAttributes[userAttNumber].len = pRtt->m_len;
			userAttNumber++;
		}
		break;
	}
	case PPME_TCP_CONNECT_X:
	{
		auto pTuple = ev->get_param_value_raw("tuple");
		userAttNumber = setTuple(p_kindling_event, pTuple, userAttNumber);
		auto pRetVal = ev->get_param_value_raw("retval");
		if(pRetVal != NULL)
		{
			strcpy(p_kindling_event->userAttributes[userAttNumber].key, "retval");
			memcpy(p_kindling_event->userAttributes[userAttNumber].value, pRetVal->m_val, pRetVal->m_len);
			p_kindling_event->userAttributes[userAttNumber].valueType = UINT64;
			p_kindling_event->userAttributes[userAttNumber].len = pRetVal->m_len;
			userAttNumber++;
		}
		break;
	}
	case PPME_TCP_DROP_E:
	case PPME_TCP_RETRANCESMIT_SKB_E:
	case PPME_TCP_SET_STATE_E:
	{
		auto pTuple = ev->get_param_value_raw("tuple");
		userAttNumber = setTuple(p_kindling_event, pTuple, userAttNumber);
		auto old_state = ev->get_param_value_raw("old_state");
		if(old_state != NULL)
		{
			strcpy(p_kindling_event->userAttributes[userAttNumber].key, "old_state");
			memcpy(p_kindling_event->userAttributes[userAttNumber].value, old_state->m_val, old_state->m_len);
			p_kindling_event->userAttributes[userAttNumber].len = old_state->m_len;
			p_kindling_event->userAttributes[userAttNumber].valueType = INT32;
			userAttNumber++;
		}
		auto new_state = ev->get_param_value_raw("new_state");
		if(new_state != NULL)
		{
			strcpy(p_kindling_event->userAttributes[userAttNumber].key, "new_state");
			memcpy(p_kindling_event->userAttributes[userAttNumber].value, new_state->m_val, new_state->m_len);
			p_kindling_event->userAttributes[userAttNumber].valueType = INT32;
			p_kindling_event->userAttributes[userAttNumber].len = new_state->m_len;
			userAttNumber++;
		}
		break;
	}
	case PPME_TCP_SEND_RESET_E:
	case PPME_TCP_RECEIVE_RESET_E:
	{
		auto pTuple = ev->get_param_value_raw("tuple");
		userAttNumber = setTuple(p_kindling_event, pTuple, userAttNumber);
		break;
	}
	default:
	{
		uint16_t paramsNumber = ev->get_num_params();
		if(paramsNumber > 8)
		{
			paramsNumber = 8;
		}
		for(auto i = 0; i < paramsNumber; i++)
		{

			strcpy(p_kindling_event->userAttributes[userAttNumber].key, (char *)ev->get_param_name(i));
			memcpy(p_kindling_event->userAttributes[userAttNumber].value, ev->get_param(i)->m_val,
			       ev->get_param(i)->m_len);
			p_kindling_event->userAttributes[userAttNumber].len = ev->get_param(i)->m_len;
			p_kindling_event->userAttributes[userAttNumber].valueType = get_type(ev->get_param_info(i)->type);
			userAttNumber++;
		}
	}
	}
	p_kindling_event->paramsNumber = userAttNumber;
	strcpy(p_kindling_event->name, (char *)ev->get_name());
	strcpy(p_kindling_event->context.tinfo.comm, (char *)threadInfo->m_comm.data());
	strcpy(p_kindling_event->context.tinfo.containerId, (char *)threadInfo->m_container_id.data());
	return 1;
}

int setTuple(kindling_event_t_for_go *p_kindling_event, const sinsp_evt_param *pTuple, int userAttNumber)
{
	if(NULL != pTuple)
	{
		auto tuple = pTuple->m_val;
		if(tuple[0] == PPM_AF_INET)
		{
			if(pTuple->m_len == 1 + 4 + 2 + 4 + 2)
			{

				strcpy(p_kindling_event->userAttributes[userAttNumber].key, "sip");
				memcpy(p_kindling_event->userAttributes[userAttNumber].value, tuple + 1, 4);
				p_kindling_event->userAttributes[userAttNumber].valueType = UINT32;
				p_kindling_event->userAttributes[userAttNumber].len = 4;
				userAttNumber++;

				strcpy(p_kindling_event->userAttributes[userAttNumber].key, "sport");
				memcpy(p_kindling_event->userAttributes[userAttNumber].value, tuple + 5, 2);
				p_kindling_event->userAttributes[userAttNumber].valueType = UINT16;
				p_kindling_event->userAttributes[userAttNumber].len = 2;
				userAttNumber++;

				strcpy(p_kindling_event->userAttributes[userAttNumber].key, "dip");
				memcpy(p_kindling_event->userAttributes[userAttNumber].value, tuple + 7, 4);
				p_kindling_event->userAttributes[userAttNumber].valueType = UINT32;
				p_kindling_event->userAttributes[userAttNumber].len = 4;
				userAttNumber++;

				strcpy(p_kindling_event->userAttributes[userAttNumber].key, "dport");
				memcpy(p_kindling_event->userAttributes[userAttNumber].value, tuple + 11, 2);
				p_kindling_event->userAttributes[userAttNumber].valueType = UINT16;
				p_kindling_event->userAttributes[userAttNumber].len = 2;
				userAttNumber++;
			}
		}
	}
	return userAttNumber;
}

uint16_t get_protocol(scap_l4_proto proto)
{
	switch(proto)
	{
	case SCAP_L4_TCP:
		return TCP;
	case SCAP_L4_UDP:
		return UDP;
	case SCAP_L4_ICMP:
		return ICMP;
	case SCAP_L4_RAW:
		return RAW;
	default:
		return UNKNOWN;
	}
}

uint16_t get_type(ppm_param_type type)
{
	switch(type)
	{
	case PT_INT8:
		return INT8;
	case PT_INT16:
		return INT16;
	case PT_INT32:
		return INT32;
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		return INT64;
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		return UINT8;
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_SYSCALLID:
		return UINT16;
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_MODE:
	case PT_UID:
	case PT_GID:
	case PT_BOOL:
	case PT_SIGSET:
		return UINT32;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		return UINT64;
	case PT_CHARBUF:
	case PT_FSPATH:
		return CHARBUF;
	case PT_BYTEBUF:
		return BYTEBUF;
	case PT_DOUBLE:
		return DOUBLE;
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	default:
		return BYTEBUF;
	}
}

uint16_t get_kindling_category(sinsp_evt *sEvt)
{
	sinsp_evt::category cat;
	sEvt->get_category(&cat);
	switch(cat.m_category)
	{
	case EC_OTHER:
		return CAT_OTHER;
	case EC_FILE:
		return CAT_FILE;
	case EC_NET:
		return CAT_NET;
	case EC_IPC:
		return CAT_IPC;
	case EC_MEMORY:
		return CAT_MEMORY;
	case EC_PROCESS:
		return CAT_PROCESS;
	case EC_SLEEP:
		return CAT_SLEEP;
	case EC_SYSTEM:
		return CAT_SYSTEM;
	case EC_SIGNAL:
		return CAT_SIGNAL;
	case EC_USER:
		return CAT_USER;
	case EC_TIME:
		return CAT_TIME;
	case EC_IO_READ:
	case EC_IO_WRITE:
	case EC_IO_OTHER:
	{
		switch(cat.m_subcategory)
		{
		case sinsp_evt::SC_FILE:
			return CAT_FILE;
		case sinsp_evt::SC_NET:
			return CAT_NET;
		case sinsp_evt::SC_IPC:
			return CAT_IPC;
		default:
			return CAT_OTHER;
		}
	}
	default:
		return CAT_OTHER;
	}
}

