###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for qemu USN-2092-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841701");
  script_version("2020-08-14T08:55:37+0000");
  script_tag(name:"last_modification", value:"2020-08-14 08:55:37 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-02-03 14:10:54 +0530 (Mon, 03 Feb 2014)");
  script_cve_id("CVE-2013-4344", "CVE-2013-4375", "CVE-2013-4377");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for qemu USN-2092-1");

  script_tag(name:"affected", value:"qemu on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Asias He discovered that QEMU incorrectly handled SCSI
controllers with more than 256 attached devices. A local user could
possibly use this flaw to elevate privileges. (CVE-2013-4344)

It was discovered that QEMU incorrectly handled Xen disks. A local guest
could possibly use this flaw to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4375)

Sibiao Luo discovered that QEMU incorrectly handled device hot-unplugging.
A local user could possibly use this flaw to cause a denial of service.
This issue only affected Ubuntu 13.10. (CVE-2013-4377)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"USN", value:"2092-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2092-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|13\.10|12\.10)");

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

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.0+noroms-0ubuntu14.13", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1.5.0+dfsg-3ubuntu5.3", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.2.0+noroms-0ubuntu2.12.10.6", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
