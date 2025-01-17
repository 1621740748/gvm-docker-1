###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for irssi USN-3465-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843350");
  script_version("2020-11-12T09:50:32+0000");
  script_tag(name:"last_modification", value:"2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-10-27 14:32:10 +0200 (Fri, 27 Oct 2017)");
  script_cve_id("CVE-2017-10965", "CVE-2017-10966", "CVE-2017-15227", "CVE-2017-15228",
                "CVE-2017-15721", "CVE-2017-15722", "CVE-2017-15723");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for irssi USN-3465-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Brian Carpenter discovered that Irssi
  incorrectly handled messages with invalid time stamps. A malicious IRC server
  could use this issue to cause Irssi to crash, resulting in a denial of service.
  (CVE-2017-10965) Brian Carpenter discovered that Irssi incorrectly handled the
  internal nick list. A malicious IRC server could use this issue to cause Irssi
  to crash, resulting in a denial of service. (CVE-2017-10966) Joseph Bisch
  discovered that Irssi incorrectly removed destroyed channels from the query
  list. A malicious IRC server could use this issue to cause Irssi to crash,
  resulting in a denial of service. (CVE-2017-15227) Hanno Bck discovered that
  Irssi incorrectly handled themes. If a user were tricked into using a malicious
  theme, an attacker could use this issue to cause Irssi to crash, resulting in a
  denial of service. (CVE-2017-15228) Joseph Bisch discovered that Irssi
  incorrectly handled certain DCC CTCP messages. A malicious IRC server could use
  this issue to cause Irssi to crash, resulting in a denial of service.
  (CVE-2017-15721) Joseph Bisch discovered that Irssi incorrectly handled certain
  channel IDs. A malicious IRC server could use this issue to cause Irssi to
  crash, resulting in a denial of service. (CVE-2017-15722) Joseph Bisch
  discovered that Irssi incorrectly handled certain long nicks or targets. A
  malicious IRC server could use this issue to cause Irssi to crash, resulting in
  a denial of service. (CVE-2017-15723)");
  script_tag(name:"affected", value:"irssi on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"USN", value:"3465-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3465-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.04|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.15-5ubuntu3.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.20-2ubuntu2.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.19-1ubuntu1.5", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
