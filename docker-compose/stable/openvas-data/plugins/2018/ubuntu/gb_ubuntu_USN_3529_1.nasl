###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-3529-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843435");
  script_version("2021-06-03T11:00:21+0000");
  script_tag(name:"last_modification", value:"2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-30 07:53:04 +0100 (Tue, 30 Jan 2018)");
  script_cve_id("CVE-2017-7829", "CVE-2017-7846", "CVE-2017-7847", "CVE-2017-7848",
                "CVE-2018-5089", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097",
                "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5013",
                "CVE-2018-5104", "CVE-2018-5117", "CVE-2018-5103");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 16:53:00 +0000 (Fri, 03 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for thunderbird USN-3529-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that a From address
  encoded with a null character is cut off in the message header display. An
  attacker could potentially exploit this to spoof the sender address.
  (CVE-2017-7829) It was discovered that it is possible to execute JavaScript in
  RSS feeds in some circumstances. If a user were tricked in to opening a
  specially crafted RSS feed, an attacker could potentially exploit this in
  combination with another vulnerability, in order to cause unspecified problems.
  (CVE-2017-7846) It was discovered that the RSS feed can leak local path names.
  If a user were tricked in to opening a specially crafted RSS feed, an attacker
  could potentially exploit this to obtain sensitive information. (CVE-2017-7847)
  It was discovered that RSS feeds are vulnerable to new line injection. If a user
  were tricked in to opening a specially crafted RSS feed, an attacker could
  potentially exploit this to cause unspecified problems. (CVE-2017-7848) Multiple
  security issues were discovered in Thunderbird. If a user were tricked in to
  opening a specially crafted website in a browsing context, an attacker could
  potentially exploit these to cause a denial of service, execute arbitrary code,
  or cause other unspecified effects. (CVE-2018-5089, CVE-2018-5095,
  CVE-2018-5096, CVE-2018-5097, CVE-2018-5098, CVE-2018-5099, CVE-2018-5102,
  CVE-2018-5013, CVE-2018-5104, CVE-2018-5117)");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"USN", value:"3529-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3529-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:52.6.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:52.6.0+build1-0ubuntu0.17.10.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:52.6.0+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
