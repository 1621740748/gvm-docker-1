###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-1367-2
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1367-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.840902");
  script_version("2020-04-21T06:28:23+0000");
  script_tag(name:"last_modification", value:"2020-04-21 06:28:23 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2012-02-21 19:00:20 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-3026");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"USN", value:"1367-2");
  script_name("Ubuntu Update for firefox USN-1367-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1367-2");
  script_tag(name:"affected", value:"firefox on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1367-1 fixed vulnerabilities in libpng. This provides the corresponding
  update for Firefox.

  Original advisory details:

  Jueri Aedla discovered that libpng did not properly verify the size used
  when allocating memory during chunk decompression. If a user or automated
  system using libpng were tricked into opening a specially crafted image,
  an attacker could exploit this to cause a denial of service or execute
  code with the privileges of the user invoking the program. (CVE-2011-3026)");
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"10.0.2+build1-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"10.0.2+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"10.0.2+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
