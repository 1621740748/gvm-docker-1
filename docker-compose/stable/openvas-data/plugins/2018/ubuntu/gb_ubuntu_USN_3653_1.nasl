###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-3653-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843528");
  script_version("2021-06-04T11:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-05-22 12:40:19 +0200 (Tue, 22 May 2018)");
  script_cve_id("CVE-2018-3639", "CVE-2017-17449", "CVE-2017-17975", "CVE-2017-18203",
                "CVE-2017-18208", "CVE-2018-8822");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 15:40:00 +0000 (Tue, 05 Mar 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3653-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"Jann Horn and Ken Johnson discovered that
microprocessors utilizing speculative execution of a memory read may allow
unauthorized memory reads via a sidechannel attack. This flaw is known as Spectre
Variant 4. A local attacker could use this to expose sensitive information,
including kernel memory. (CVE-2018-3639)

It was discovered that the netlink subsystem in the Linux kernel did not
properly restrict observations of netlink messages to the appropriate net
namespace. A local attacker could use this to expose sensitive information
(kernel netlink traffic). (CVE-2017-17449)

Tuba Yavuz discovered that a double-free error existed in the USBTV007
driver of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-17975)

It was discovered that a race condition existed in the Device Mapper
component of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash). (CVE-2017-18203)

It was discovered that an infinite loop could occur in the madvise(2)
implementation in the Linux kernel in certain circumstances. A local
attacker could use this to cause a denial of service (system hang).
(CVE-2017-18208)

Silvio Cesare discovered a buffer overwrite existed in the NCPFS
implementation in the Linux kernel. A remote attacker controlling a
malicious NCPFS server could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-8822)");
  script_tag(name:"affected", value:"linux on Ubuntu 17.10");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3653-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3653-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU17\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-43-generic", ver:"4.13.0-43.48", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-43-generic-lpae", ver:"4.13.0-43.48", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-43-lowlatency", ver:"4.13.0-43.48", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.13.0.43.46", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.13.0.43.46", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.13.0.43.46", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
