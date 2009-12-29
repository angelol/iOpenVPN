#include "config.h"
#include "syshead.h"
#include "socket.h"
#include "tun.h"


/* --ifconfig-nowarn disables some options sanity checking */
static const char ifconfig_warn_how_to_silence[] = "(silence this warning with --ifconfig-nowarn)";

/*
 * If !tun, make sure ifconfig_remote_netmask looks
 *  like a netmask.
 *
 * If tun, make sure ifconfig_remote_netmask looks
 *  like an IPv4 address.
 */
static void
ifconfig_sanity_check (bool tun, in_addr_t addr, int topology)
{
	fprintf(stderr, "%s called\n", __FUNCTION__);
  struct gc_arena gc = gc_new ();
  const bool looks_like_netmask = ((addr & 0xFF000000) == 0xFF000000);
  if (tun)
    {
      if (looks_like_netmask && (topology == TOP_NET30 || topology == TOP_P2P))
	msg (M_WARN, "WARNING: Since you are using --dev tun with a point-to-point topology, the second argument to --ifconfig must be an IP address.  You are using something (%s) that looks more like a netmask. %s",
	     print_in_addr_t (addr, 0, &gc),
	     ifconfig_warn_how_to_silence);
    }
  else /* tap */
    {
      if (!looks_like_netmask)
	msg (M_WARN, "WARNING: Since you are using --dev tap, the second argument to --ifconfig must be a netmask, for example something like 255.255.255.0. %s",
	     ifconfig_warn_how_to_silence);
    }
  gc_free (&gc);
}

/*
 * Check that --local and --remote addresses do not
 * clash with ifconfig addresses or subnet.
 */
static void
check_addr_clash (const char *name,
		  int type,
		  in_addr_t public,
		  in_addr_t local,
		  in_addr_t remote_netmask)
{
	fprintf(stderr, "%s called\n", __FUNCTION__);
  struct gc_arena gc = gc_new ();
#if 0
  msg (M_INFO, "CHECK_ADDR_CLASH type=%d public=%s local=%s, remote_netmask=%s",
       type,
       print_in_addr_t (public, 0, &gc),
       print_in_addr_t (local, 0, &gc),
       print_in_addr_t (remote_netmask, 0, &gc));
#endif

  if (public)
    {
      if (type == DEV_TYPE_TUN)
	{
	  const in_addr_t test_netmask = 0xFFFFFF00;
	  const in_addr_t public_net = public & test_netmask;
	  const in_addr_t local_net = local & test_netmask;
	  const in_addr_t remote_net = remote_netmask & test_netmask;

	  if (public == local || public == remote_netmask)
	    msg (M_WARN,
		 "WARNING: --%s address [%s] conflicts with --ifconfig address pair [%s, %s]. %s",
		 name,
		 print_in_addr_t (public, 0, &gc),
		 print_in_addr_t (local, 0, &gc),
		 print_in_addr_t (remote_netmask, 0, &gc),
		 ifconfig_warn_how_to_silence);

	  if (public_net == local_net || public_net == remote_net)
	    msg (M_WARN,
		 "WARNING: potential conflict between --%s address [%s] and --ifconfig address pair [%s, %s] -- this is a warning only that is triggered when local/remote addresses exist within the same /24 subnet as --ifconfig endpoints. %s",
		 name,
		 print_in_addr_t (public, 0, &gc),
		 print_in_addr_t (local, 0, &gc),
		 print_in_addr_t (remote_netmask, 0, &gc),
		 ifconfig_warn_how_to_silence);
	}
      else if (type == DEV_TYPE_TAP)
	{
	  const in_addr_t public_network = public & remote_netmask;
	  const in_addr_t virtual_network = local & remote_netmask;
	  if (public_network == virtual_network)
	    msg (M_WARN,
		 "WARNING: --%s address [%s] conflicts with --ifconfig subnet [%s, %s] -- local and remote addresses cannot be inside of the --ifconfig subnet. %s",
		 name,
		 print_in_addr_t (public, 0, &gc),
		 print_in_addr_t (local, 0, &gc),
		 print_in_addr_t (remote_netmask, 0, &gc),
		 ifconfig_warn_how_to_silence);
	}
    }
  gc_free (&gc);
}



/*
 * Return a status string describing wait state.
 */
const char *
tun_stat (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc)
{
	fprintf(stderr, "%s called\n", __FUNCTION__);
	
  struct buffer out = alloc_buf_gc (64, gc);
  if (tt)
    {
      if (rwflags & EVENT_READ)
	{
	  buf_printf (&out, "T%s",
		      (tt->rwflags_debug & EVENT_READ) ? "R" : "r");
#ifdef WIN32
	  buf_printf (&out, "%s",
		      overlapped_io_state_ascii (&tt->reads));
#endif
	}
      if (rwflags & EVENT_WRITE)
	{
	  buf_printf (&out, "T%s",
		      (tt->rwflags_debug & EVENT_WRITE) ? "W" : "w");
#ifdef WIN32
	  buf_printf (&out, "%s",
		      overlapped_io_state_ascii (&tt->writes));
#endif
	}
    }
  else
    {
      buf_printf (&out, "T?");
    }
  return BSTR (&out);
}

bool
is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
  ASSERT (match_type);
  if (!dev)
    return false;
  if (dev_type)
    return !strcmp (dev_type, match_type);
  else
    return !strncmp (dev, match_type, strlen (match_type));
}

int
dev_type_enum (const char *dev, const char *dev_type)
{
  if (is_dev_type (dev, dev_type, "tun"))
    return DEV_TYPE_TUN;
  else if (is_dev_type (dev, dev_type, "tap"))
    return DEV_TYPE_TAP;
  else if (is_dev_type (dev, dev_type, "null"))
    return DEV_TYPE_NULL;
  else
    return DEV_TYPE_UNDEF;
}

const char *
dev_type_string (const char *dev, const char *dev_type)
{
	fprintf(stderr, "%s called\n", __FUNCTION__);
	return "tun";
	
  switch (dev_type_enum (dev, dev_type))
    {
    case DEV_TYPE_TUN:
      return "tun";
    case DEV_TYPE_TAP:
      return "tap";
    case DEV_TYPE_NULL:
      return "null";
    default:
      return "[unknown-dev-type]";
    }
}


void
close_tun (struct tuntap *tt)
{
	msg (D_PUSH, "%s called\n", __FUNCTION__);
}


/*
 * Return a string to be used for options compatibility check
 * between peers.
 */
const char *
ifconfig_options_string (const struct tuntap* tt, bool remote, bool disable, struct gc_arena *gc)
{
	fprintf(stderr, "%s called\n", __FUNCTION__);
  struct buffer out = alloc_buf_gc (256, gc);
	buf_printf (&out, "[undef]");
  return BSTR (&out);
}


void open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
	fprintf(stderr, "%s called\n", __FUNCTION__);
	
	bpf_open(tt->bpf_ctx);
	bpf_attach(tt->bpf_ctx, "lo0");
}

int read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
	fprintf(stderr, "%s called\n", __FUNCTION__);
	
	return bpf_wait_and_recv(tt->bpf_ctx, buf, len);
}

int write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
	msg (D_PUSH, "%s called\n", __FUNCTION__);
	msg (D_PUSH, "Trying to write %d bytes to BPF", len);
	
	tt->bpf_ctx->buf = buf;
	tt->bpf_ctx->bufsize = len;
	return bpf_write_packet(tt->bpf_ctx);
}




/* execute the ifconfig command through the shell */
void do_ifconfig (struct tuntap *tt, const char *actual, int tun_mtu, const struct env_set *es)
{
	
}


/*
 * For TAP-style devices, generate a broadcast address.
 */
static in_addr_t
generate_ifconfig_broadcast_addr (in_addr_t local,
				  in_addr_t netmask)
{
  return local | ~netmask;
}


const char *dev_component_in_dev_node (const char *dev_node)
{
  const char *ret;
  const int dirsep = OS_SPECIFIC_DIRSEP;

  if (dev_node)
    {
      ret = strrchr (dev_node, dirsep);
      if (ret && *ret)
	++ret;
      else
	ret = dev_node;
      if (*ret)
	return ret;
    }
  return NULL;
}


static struct tuntap *dummy_init_tun(const char *dev,       /* --dev option */
	  const char *dev_type,  /* --dev-type option */
	  int topology,          /* one of the TOP_x values */
	  const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	  const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	  in_addr_t local_public,
	  in_addr_t remote_public,
	  const bool strict_warn,
	  struct env_set *es)
{
	struct gc_arena gc = gc_new ();
  struct tuntap *tt;

  ALLOC_OBJ (tt, struct tuntap);
  clear_tuntap (tt);

  tt->type = dev_type_enum (dev, dev_type);
  tt->topology = topology;

  if (ifconfig_local_parm && ifconfig_remote_netmask_parm)
    {
      bool tun = false;
      const char *ifconfig_local = NULL;
      const char *ifconfig_remote_netmask = NULL;
      const char *ifconfig_broadcast = NULL;

      /*
       * We only handle TUN/TAP devices here, not --dev null devices.
       */
      tun = is_tun_p2p (tt);

      /*
       * Convert arguments to binary IPv4 addresses.
       */

      tt->local = getaddr (
			   GETADDR_RESOLVE
			   | GETADDR_HOST_ORDER
			   | GETADDR_FATAL_ON_SIGNAL
			   | GETADDR_FATAL,
			   ifconfig_local_parm,
			   0,
			   NULL,
			   NULL);

      tt->remote_netmask = getaddr (
				    (tun ? GETADDR_RESOLVE : 0)
				    | GETADDR_HOST_ORDER
				    | GETADDR_FATAL_ON_SIGNAL
				    | GETADDR_FATAL,
				    ifconfig_remote_netmask_parm,
				    0,
				    NULL,
				    NULL);

      /*
       * Look for common errors in --ifconfig parms
       */
      if (strict_warn)
	{
	  ifconfig_sanity_check (tt->type == DEV_TYPE_TUN, tt->remote_netmask, tt->topology);

	  /*
	   * If local_public or remote_public addresses are defined,
	   * make sure they do not clash with our virtual subnet.
	   */

	  check_addr_clash ("local",
			    tt->type,
			    local_public,
			    tt->local,
			    tt->remote_netmask);

	  check_addr_clash ("remote",
			    tt->type,
			    remote_public,
			    tt->local,
			    tt->remote_netmask);
	}

      /*
       * Set ifconfig parameters
       */
      ifconfig_local = print_in_addr_t (tt->local, 0, &gc);
      ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, 0, &gc);

      /*
       * If TAP-style interface, generate broadcast address.
       */
      if (!tun)
	{
	  tt->broadcast = generate_ifconfig_broadcast_addr (tt->local, tt->remote_netmask);
	  ifconfig_broadcast = print_in_addr_t (tt->broadcast, 0, &gc);
	}

      /*
       * Set environmental variables with ifconfig parameters.
       */
      if (es)
	{
	  setenv_str (es, "ifconfig_local", ifconfig_local);
	  if (tun)
	    {
	      setenv_str (es, "ifconfig_remote", ifconfig_remote_netmask);
	    }
	  else
	    {
	      setenv_str (es, "ifconfig_netmask", ifconfig_remote_netmask);
	      setenv_str (es, "ifconfig_broadcast", ifconfig_broadcast);
	    }
	}

      tt->did_ifconfig_setup = true;
    }
  gc_free (&gc);
  return tt;
}
void
clear_tuntap (struct tuntap *tuntap)
{
  CLEAR (*tuntap);
#ifdef WIN32
  tuntap->hand = NULL;
#else
  tuntap->fd = -1;
#endif
#ifdef TARGET_SOLARIS
  tuntap->ip_fd = -1;
#endif
  tuntap->ipv6 = false;
}


/*
 * Return true for point-to-point topology, false for subnet topology
 */
bool
is_tun_p2p (const struct tuntap *tt)
{
  bool tun = false;

  if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
    tun = false;
  else if (tt->type == DEV_TYPE_TUN)
    tun = true;
  else
    ASSERT (0); /* should have been caught in init_tun ... JYFIXME -- was hit */

  return tun;
}

/*
 * Init tun/tap object.
 *
 * Set up tuntap structure for ifconfig,
 * but don't execute yet.
 */
struct tuntap *
init_tun (const char *dev,       /* --dev option */
	  const char *dev_type,  /* --dev-type option */
	  int topology,          /* one of the TOP_x values */
	  const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	  const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	  in_addr_t local_public,
	  in_addr_t remote_public,
	  const bool strict_warn,
	  struct env_set *es)
{
	msg (D_PUSH, "%s called\n", __FUNCTION__);
	struct tuntap *tt = dummy_init_tun(dev, dev_type, topology, ifconfig_local_parm, ifconfig_remote_netmask_parm, local_public, remote_public, strict_warn, es);
	tt->bpf_ctx = bpf_new();
	return tt;
}


/*
 * Platform specific tun initializations
 */
void
init_tun_post (struct tuntap *tt,
	       const struct frame *frame,
	       const struct tuntap_options *options)
{
  tt->options = *options;
}




