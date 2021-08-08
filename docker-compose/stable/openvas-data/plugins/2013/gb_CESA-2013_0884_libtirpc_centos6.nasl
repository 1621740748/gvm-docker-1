###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libtirpc CESA-2013:0884 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881743");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-05-31 09:51:46 +0530 (Fri, 31 May 2013)");
  script_cve_id("CVE-2013-1950");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for libtirpc CESA-2013:0884 centos6");

  script_xref(name:"CESA", value:"2013:0884");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019768.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtirpc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libtirpc on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"These packages provide a transport-independent RPC (remote procedure call)
  implementation.

  A flaw was found in the way libtirpc decoded RPC requests. A
  specially-crafted RPC request could cause libtirpc to attempt to free a
  buffer provided by an application using the library, even when the buffer
  was not dynamically allocated. This could cause an application using
  libtirpc, such as rpcbind, to crash. (CVE-2013-1950)

  Red Hat would like to thank Michael Armstrong for reporting this issue.

  Users of libtirpc should upgrade to these updated packages, which contain a
  backported patch to correct this issue. All running applications using
  libtirpc must be restarted for the update to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"libtirpc", rpm:"libtirpc~0.2.1~6.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtirpc-devel", rpm:"libtirpc-devel~0.2.1~6.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
