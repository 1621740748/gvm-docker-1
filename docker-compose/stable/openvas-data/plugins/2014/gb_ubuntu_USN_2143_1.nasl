###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for cups-filters USN-2143-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841752");
  script_version("2020-11-19T14:17:11+0000");
  script_tag(name:"last_modification", value:"2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2014-03-17 13:38:54 +0530 (Mon, 17 Mar 2014)");
  script_cve_id("CVE-2013-6473", "CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for cups-filters USN-2143-1");

  script_tag(name:"affected", value:"cups-filters on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Florian Weimer discovered that cups-filters incorrectly
handled memory in the urftopdf filter. An attacker could possibly use this
issue to execute arbitrary code with the privileges of the lp user. This issue
only affected Ubuntu 13.10. (CVE-2013-6473)

Florian Weimer discovered that cups-filters incorrectly handled memory
in the pdftoopvp filter. An attacker could possibly use this issue to
execute arbitrary code with the privileges of the lp user. (CVE-2013-6474,
CVE-2013-6475)

Florian Weimer discovered that cups-filters did not restrict driver
directories in the pdftoopvp filter. An attacker could possibly use this
issue to execute arbitrary code with the privileges of the lp user.
(CVE-2013-6476)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"USN", value:"2143-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2143-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-filters'
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

  if ((res = isdpkgvuln(pkg:"cups-filters", ver:"1.0.18-0ubuntu0.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"cups-filters", ver:"1.0.40-0ubuntu1.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"cups-filters", ver:"1.0.24-2ubuntu0.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
