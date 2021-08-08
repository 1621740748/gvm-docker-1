###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for icu USN-2522-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842117");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:51:21 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419",
                "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926",
                "CVE-2014-9654", "CVE-2014-7940");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for icu USN-2522-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that ICU incorrectly
handled memory operations when processing fonts. If an application using ICU
processed crafted data, an attacker could cause it to crash or potentially
execute arbitrary code with the privileges of the user invoking the program.
This issue only affected Ubuntu 12.04 LTS. (CVE-2013-1569, CVE-2013-2383,
CVE-2013-2384, CVE-2013-2419)

It was discovered that ICU incorrectly handled memory operations when
processing fonts. If an application using ICU processed crafted data, an
attacker could cause it to crash or potentially execute arbitrary code with
the privileges of the user invoking the program. (CVE-2014-6585,
CVE-2014-6591)

It was discovered that ICU incorrectly handled memory operations when
processing regular expressions. If an application using ICU processed
crafted data, an attacker could cause it to crash or potentially execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2014-7923, CVE-2014-7926, CVE-2014-9654)

It was discovered that ICU collator implementation incorrectly handled
memory operations. If an application using ICU processed crafted data, an
attacker could cause it to crash or potentially execute arbitrary code with
the privileges of the user invoking the program. (CVE-2014-7940)");
  script_tag(name:"affected", value:"icu on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"USN", value:"2522-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2522-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.10|14\.04 LTS|12\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"libicu52:amd64", ver:"52.1-6ubuntu0.2", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libicu52:i386", ver:"52.1-6ubuntu0.2", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libicu52:amd64", ver:"52.1-3ubuntu0.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libicu52:i386", ver:"52.1-3ubuntu0.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libicu48", ver:"4.8.1.1-3ubuntu0.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
