###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-3477-4
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
  script_oid("1.3.6.1.4.1.25623.1.0.843404");
  script_version("2021-06-04T11:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-05 23:55:23 +0100 (Fri, 05 Jan 2018)");
  script_cve_id("CVE-2017-7826", "CVE-2017-7827", "CVE-2017-7828", "CVE-2017-7830",
                "CVE-2017-7831", "CVE-2017-7832", "CVE-2017-7833", "CVE-2017-7834",
                "CVE-2017-7835", "CVE-2017-7837", "CVE-2017-7838", "CVE-2017-7842",
                "CVE-2017-7839", "CVE-2017-7840");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:06:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for firefox USN-3477-4");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3477-1 fixed vulnerabilities in Firefox.
  The update introduced a crash reporting issue where background tab crash reports
  were sent to Mozilla without user opt-in. This update fixes the problem. We
  apologize for the inconvenience. Original advisory details: Multiple security
  issues were discovered in Firefox. If a user were tricked in to opening a
  specially crafted website, an attacker could potentially exploit these to cause
  a denial of service, read uninitialized memory, obtain sensitive information,
  bypass same-origin restrictions, bypass CSP protections, bypass mixed content
  blocking, spoof the addressbar, or execute arbitrary code. (CVE-2017-7826,
  CVE-2017-7827, CVE-2017-7828, CVE-2017-7830, CVE-2017-7831, CVE-2017-7832,
  CVE-2017-7833, CVE-2017-7834, CVE-2017-7835, CVE-2017-7837, CVE-2017-7838,
  CVE-2017-7842) It was discovered that javascript: URLs pasted in to the
  addressbar would be executed instead of being blocked in some circumstances. If
  a user were tricked in to copying a specially crafted URL in to the addressbar,
  an attacker could potentially exploit this to conduct cross-site scripting (XSS)
  attacks. (CVE-2017-7839) It was discovered that exported bookmarks do not strip
  script elements from user-supplied tags. If a user were tricked in to adding
  specially crafted tags to bookmarks, exporting them and then opening the
  resulting HTML file, an attacker could potentially exploit this to conduct
  cross-site scripting (XSS) attacks. (CVE-2017-7840)");
  script_tag(name:"affected", value:"firefox on Ubuntu 17.10,
  Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"USN", value:"3477-4");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3477-4/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|17\.04|16\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"57.0.3+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"57.0.3+build1-0ubuntu0.17.10.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"57.0.3+build1-0ubuntu0.17.04.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"57.0.3+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
