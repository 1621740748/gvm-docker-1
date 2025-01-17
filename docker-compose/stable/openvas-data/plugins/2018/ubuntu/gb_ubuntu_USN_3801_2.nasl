###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-3801-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.843829");
  script_version("2021-06-04T02:00:20+0000");
  script_cve_id("CVE-2018-12388", "CVE-2018-12390", "CVE-2018-12392", "CVE-2018-12393",
                "CVE-2018-12398", "CVE-2018-12399", "CVE-2018-12401", "CVE-2018-12402",
                "CVE-2018-12403", "CVE-2018-12395", "CVE-2018-12396", "CVE-2018-12397");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 19:03:00 +0000 (Fri, 01 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-11-26 15:08:06 +0100 (Mon, 26 Nov 2018)");
  script_name("Ubuntu Update for firefox USN-3801-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|18\.04 LTS|18\.10|16\.04 LTS)");

  script_xref(name:"USN", value:"3801-2");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3801-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the USN-3801-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3801-1 fixed vulnerabilities in Firefox. The update introduced various
minor regressions. This update fixes the problems.

We apologize for the inconvenience.

Original advisory details:

Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, bypass CSP
restrictions, spoof the protocol registration notification bar, leak
SameSite cookies, bypass mixed content warnings, or execute arbitrary
code. (CVE-2018-12388, CVE-2018-12390, CVE-2018-12392, CVE-2018-12393,
CVE-2018-12398, CVE-2018-12399, CVE-2018-12401, CVE-2018-12402,
CVE-2018-12403)

Multiple security issues were discovered with WebExtensions in Firefox.
If a user were tricked in to installing a specially crafted extension, an
attacker could potentially exploit these to bypass domain restrictions,
gain additional privileges, or run content scripts in local pages without
permission. (CVE-2018-12395, CVE-2018-12396, CVE-2018-12397)");

  script_tag(name:"affected", value:"firefox on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"63.0.3+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"63.0.3+build1-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"63.0.3+build1-0ubuntu0.18.10.1", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"63.0.3+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
