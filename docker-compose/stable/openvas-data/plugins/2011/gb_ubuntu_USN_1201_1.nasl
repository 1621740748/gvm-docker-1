###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1201-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1201-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840740");
  script_version("2021-05-19T13:27:56+0200");
  script_tag(name:"last_modification", value:"2021-05-19 13:27:56 +0200 (Wed, 19 May 2021)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:08:00 +0000 (Mon, 27 Jul 2020)");
  script_xref(name:"USN", value:"1201-1");
  script_cve_id("CVE-2011-1020", "CVE-2011-1493", "CVE-2011-1770", "CVE-2011-2484", "CVE-2011-2492");
  script_name("Ubuntu Update for linux USN-1201-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.10");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1201-1");
  script_tag(name:"affected", value:"linux on Ubuntu 10.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that the /proc filesystem did not correctly handle
  permission changes when programs executed. A local attacker could hold open
  files to examine details about programs running with higher privileges,
  potentially increasing the chances of exploiting additional
  vulnerabilities. (CVE-2011-1020)

  Dan Rosenberg discovered that the X.25 Rose network stack did not correctly
  handle certain fields. If a system was running with Rose enabled, a remote
  attacker could send specially crafted traffic to gain root privileges.
  (CVE-2011-1493)

  Dan Rosenberg discovered that the DCCP stack did not correctly handle
  certain packet structures. A remote attacker could exploit this to crash
  the system, leading to a denial of service. (CVE-2011-1770)

  Vasiliy Kulikov discovered that taskstats listeners were not correctly
  handled. A local attacker could exploit this to exhaust memory and CPU
  resources, leading to a denial of service. (CVE-2011-2484)

  It was discovered that Bluetooth l2cap and rfcomm did not correctly
  initialize structures. A local attacker could exploit this to read portions
  of the kernel stack, leading to a loss of privacy. (CVE-2011-2492)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic-pae", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-omap", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc-smp", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc64-smp", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-server", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-versatile", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-virtual", ver:"2.6.35-30.59", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
