###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mantis FEDORA-2013-20176
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.867084");
  script_version("2019-11-12T13:06:17+0000");
  script_tag(name:"last_modification", value:"2019-11-12 13:06:17 +0000 (Tue, 12 Nov 2019)");
  script_tag(name:"creation_date", value:"2013-11-26 10:08:52 +0530 (Tue, 26 Nov 2013)");
  script_cve_id("CVE-2013-4460", "CVE-2013-1930", "CVE-2013-1931", "CVE-2013-1883");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Update for mantis FEDORA-2013-20176");


  script_tag(name:"affected", value:"mantis on Fedora 18");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2013-20176");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-November/122555.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mantis'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC18");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"mantis", rpm:"mantis~1.2.15~3.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
