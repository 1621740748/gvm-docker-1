###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libpng FEDORA-2012-5515
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
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2012-April/079039.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864175");
  script_version("2020-04-21T06:28:23+0000");
  script_tag(name:"last_modification", value:"2020-04-21 06:28:23 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2012-04-26 10:32:12 +0530 (Thu, 26 Apr 2012)");
  script_cve_id("CVE-2011-3048", "CVE-2011-3045", "CVE-2011-3026", "CVE-2011-2501",
                "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"FEDORA", value:"2012-5515");
  script_name("Fedora Update for libpng FEDORA-2012-5515");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC15");
  script_tag(name:"affected", value:"libpng on Fedora 15");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.49~1.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
