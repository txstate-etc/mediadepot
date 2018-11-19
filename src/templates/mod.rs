use maud::{ DOCTYPE, PreEscaped, html, Markup };

fn header(title: &str) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no";
            title { (title) }
            link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css" integrity="sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb" crossorigin="anonymous";
            link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css";
            link rel="stylesheet" href="/static/css/mediadepot.css";
            link rel="shortcut icon" href="/favicon.ico" type="image/x-icon";
        }
    }
}

fn footer(email: &str) -> Markup {
    html! {
        footer {
            "Need Help? Please contact "
            a.footer-link href={ "mailto" (email) } {
                (email)
            }
        }
        (PreEscaped(r#"
            <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous" ></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.3/umd/popper.min.js" integrity="sha384-vFJXuSJphROIrBnz7yo7oB41mKfc8JzQZiCq4NCceLEaO4IHwicKwpJf9c9IpFgh" crossorigin="anonymous" ></script>
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/js/bootstrap.min.js" integrity="sha384-alpBpkh1PFOepccYVYDB4do5UnbKysX5WZXm3XxPqe5iKTfUKjNkCk9SaVuEZflJ" crossorigin="anonymous" ></script>
            <script>
                jQuery(function($) {
                    $('.btn-logout').click(function(e) {
                        window.location.href = "/logout";
                    });
                });
            </script>
        "#))
    }
}

pub fn layout(title: &str, email: &str, content: Markup) -> Markup {
    html! {
        (header(title))
        body {
            div.container-fluid {
                div.navbar {
                    div.navbar-brand {
                        img.youstar-logo src="/static/jpg/MediaDepot-ysstudio.jpg" alt=(title);
                    }
                    button.btn.btn-primary.navbar-btn.btn-sm.btn-logout type="button" {
                        span.logout-text { "Logout" }
                        i.fa.fa-sign-out aria-hidden="true" { }
                    }
                }
            }
            (content)
            (footer(email))
        }
    }
}

pub fn error(err: &str) -> Markup {
    html! {
        div.container.main-content {
            h1.sr-only { "Error" }
            div.error {
                (err)
            }
        }
    }
}
