###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-ti-omap4 USN-2335-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841954");
  script_version("2020-08-18T09:42:52+0000");
  script_tag(name:"last_modification", value:"2020-08-18 09:42:52 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-09-03 05:56:24 +0200 (Wed, 03 Sep 2014)");
  script_cve_id("CVE-2014-3917", "CVE-2014-4027", "CVE-2014-4171", "CVE-2014-4652",
                "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656",
                "CVE-2014-4667", "CVE-2014-5077");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Ubuntu Update for linux-ti-omap4 USN-2335-1");

  script_tag(name:"affected", value:"linux-ti-omap4 on Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"An flaw was discovered in the Linux kernel's audit subsystem
when auditing certain syscalls. A local attacker could exploit this flaw to
obtain potentially sensitive single-bit values from kernel memory or cause a
denial of service (OOPS). (CVE-2014-3917)

An information leak was discovered in the rd_mcp backend of the iSCSI
target subsystem in the Linux kernel. A local user could exploit this flaw
to obtain sensitive information from ramdisk_mcp memory by leveraging
access to a SCSI initiator. (CVE-2014-4027)

Sasha Levin reported an issue with the Linux kernel's shared memory
subsystem when used with range notifications and hole punching. A local
user could exploit this flaw to cause a denial of service. (CVE-2014-4171)

An information leak was discovered in the control implementation of the
Advanced Linux Sound Architecture (ALSA) subsystem in the Linux kernel. A
local user could exploit this flaw to obtain sensitive information from
kernel memory. (CVE-2014-4652)

A use-after-free flaw was discovered in the Advanced Linux Sound
Architecture (ALSA) control implementation of the Linux kernel. A local
user could exploit this flaw to cause a denial of service (system crash).
(CVE-2014-4653)

A authorization bug was discovered with the snd_ctl_elem_add function of
the Advanced Linux Sound Architecture (ALSA) in the Linux kernel. A local
user could exploit his bug to cause a denial of service (remove kernel
controls). (CVE-2014-4654)

A flaw discovered in how the snd_ctl_elem function of the Advanced Linux
Sound Architecture (ALSA) handled a reference count. A local user could
exploit this flaw to cause a denial of service (integer overflow and limit
bypass). (CVE-2014-4655)

An integer overflow flaw was discovered in the control implementation of
the Advanced Linux Sound Architecture (ALSA). A local user could exploit
this flaw to cause a denial of service (system crash). (CVE-2014-4656)

An integer underflow flaw was discovered in the Linux kernel's handling of
the backlog value for certain SCTP packets. A remote attacker could exploit
this flaw to cause a denial of service (socket outage) via a crafted SCTP
packet. (CVE-2014-4667)

Jason Gunthorpe reported a flaw with SCTP authentication in the Linux
kernel. A remote attacker could exploit this flaw to cause a denial of
service (NULL pointer dereference and OOPS). (CVE-2014-5077)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"USN", value:"2335-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2335-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-1452-omap4", ver:"3.2.0-1452.72", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
