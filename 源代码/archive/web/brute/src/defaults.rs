#![forbid(unsafe_code)]

/// 内置分类默认口令库：按产品分类，题目点名产品时优先使用
pub fn get(cat: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |pairs: &[(&str, &str)]| {
        for (u, p) in pairs {
            let item = (u.to_string(), p.to_string());
            if !out.contains(&item) {
                out.push(item);
            }
        }
    };
    match cat {
        "eyou" => push(EYOU),
        "phpmyadmin" => push(PHPMYADMIN),
        "tomcat" => push(TOMCAT),
        "router" => push(ROUTER),
        "dvr" => push(DVR),
        "weblogic" => push(WEBLOGIC),
        "all" => {
            for c in [EYOU, PHPMYADMIN, TOMCAT, ROUTER, DVR, WEBLOGIC] {
                push(c);
            }
        }
        other => {
            eprintln!("[defaults] 未知分类 {other}，可用: all|eyou|phpmyadmin|tomcat|router|dvr|weblogic");
        }
    }
    out
}

const EYOU: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "admin888"),
    ("admin", "admin123"),
    ("admin", "000000"),
    ("admin", "111111"),
    ("admin", "12345"),
    ("admin", "root"),
    ("admin", "password"),
    ("postmaster", "postmaster"),
    ("postmaster", "123456"),
    ("webadmin", "webadmin"),
];

const PHPMYADMIN: &[(&str, &str)] = &[
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "admin"),
    ("root", "12345"),
    ("admin", "admin"),
    ("pma", "pma"),
    ("test", "test"),
];

const TOMCAT: &[(&str, &str)] = &[
    ("tomcat", "tomcat"),
    ("admin", "admin"),
    ("admin", "manager"),
    ("manager", "manager"),
    ("tomcat", "s3cret"),
    ("admin", "s3cret"),
    ("manager", "s3cret"),
    ("tomcat", "tomcat123"),
];

const ROUTER: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "000000"),
    ("admin", "888888"),
    ("root", "root"),
    ("root", "123456"),
    ("user", "user"),
];

const DVR: &[(&str, &str)] = &[
    ("admin", "123456"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", "111111"),
    ("admin", "admin"),
    ("root", "root"),
    ("user", "user"),
];

const WEBLOGIC: &[(&str, &str)] = &[
    ("weblogic", "weblogic"),
    ("weblogic", "weblogic123"),
    ("weblogic", "Welcome1"),
    ("weblogic", "Admin123"),
    ("admin", "admin"),
    ("system", "system"),
];