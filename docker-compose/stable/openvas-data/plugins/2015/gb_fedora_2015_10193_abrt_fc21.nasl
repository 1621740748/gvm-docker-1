###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for abrt FEDORA-2015-10193
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
  script_oid("1.3.6.1.4.1.25623.1.0.869478");
  script_version("2020-01-24T07:57:30+0000");
  script_tag(name:"last_modification", value:"2020-01-24 07:57:30 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-07-01 06:27:48 +0200 (Wed, 01 Jul 2015)");
  script_cve_id("CVE-2015-3315", "CVE-2015-3142", "CVE-2015-1869", "CVE-2015-1870",
                "CVE-2015-3151", "CVE-2015-3150", "CVE-2015-3159", "CVE-2015-3147");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for abrt FEDORA-2015-10193");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'abrt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"abrt on Fedora 21");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-10193");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-June/161247.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC21");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC21")
{

  if ((res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.3.0~7.fc21", rls:"FC21")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
