###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2011:1386 centos5 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-October/018127.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881406");
  script_version("2020-08-04T07:16:50+0000");
  script_tag(name:"last_modification", value:"2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-07-30 17:46:47 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-4067", "CVE-2011-1160", "CVE-2011-1585", "CVE-2011-1833",
                "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2695", "CVE-2011-2699",
                "CVE-2011-2723", "CVE-2011-2942", "CVE-2011-3131", "CVE-2011-3188",
                "CVE-2011-3191", "CVE-2011-3209", "CVE-2011-3347");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:1386");
  script_name("CentOS Update for kernel CESA-2011:1386 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * The maximum file offset handling for ext4 file systems could allow a
  local, unprivileged user to cause a denial of service. (CVE-2011-2695,
  Important)

  * IPv6 fragment identification value generation could allow a remote
  attacker to disrupt a target system's networking, preventing legitimate
  users from accessing its services. (CVE-2011-2699, Important)

  * A malicious CIFS (Common Internet File System) server could send a
  specially-crafted response to a directory read request that would result in
  a denial of service or privilege escalation on a system that has a CIFS
  share mounted. (CVE-2011-3191, Important)

  * A local attacker could use mount.ecryptfs_private to mount (and then
  access) a directory they would otherwise not have access to. Note: To
  correct this issue, the RHSA-2011:1241 ecryptfs-utils update must also be
  installed. (CVE-2011-1833, Moderate)

  * A flaw in the taskstats subsystem could allow a local, unprivileged user
  to cause excessive CPU time and memory use. (CVE-2011-2484, Moderate)

  * Mapping expansion handling could allow a local, unprivileged user to
  cause a denial of service. (CVE-2011-2496, Moderate)

  * GRO (Generic Receive Offload) fields could be left in an inconsistent
  state. An attacker on the local network could use this flaw to cause a
  denial of service. GRO is enabled by default in all network drivers that
  support it. (CVE-2011-2723, Moderate)

  * RHSA-2011:1065 introduced a regression in the Ethernet bridge
  implementation. If a system had an interface in a bridge, and an attacker
  on the local network could send packets to that interface, they could cause
  a denial of service on that system. Xen hypervisor and KVM (Kernel-based
  Virtual Machine) hosts often deploy bridge interfaces. (CVE-2011-2942,
  Moderate)

  * A flaw in the Xen hypervisor IOMMU error handling implementation could
  allow a privileged guest user, within a guest operating system that has
  direct control of a PCI device, to cause performance degradation on the
  host and possibly cause it to hang. (CVE-2011-3131, Moderate)

  * IPv4 and IPv6 protocol sequence number and fragment ID generation could
  allow a man-in-the-middle attacker to inject packets and possibly hijack
  connections. Protocol sequence number and fragment IDs are now more random.
  (CVE-2011-3188, Moderate)

  * A flaw in the kernel's clock implementation could allow a local,
  unprivileged user to cause a denial of service. (CVE-2011-3209, Moderat ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.7.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
