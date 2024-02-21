package rules

# by default we deny everything
default allow := false

users := {
    "alice":   {"manager": "charlie", "title": "salesperson"},
    "bob":     {"manager": "charlie", "title": "salesperson"},
    "charlie": {"manager": "dave",    "title": "manager"},
    "dave":    {"manager": null,      "title": "ceo"}
}


allow {
  input.path == ["cars"]
  input.method == "GET"
}

test_car_read_positive {
    in = {
       "method": "GET",
       "path": ["cars"],
       "user": "alice"
    }
    allow == true with input as in
}

test_car_read_negative {
    in = {
       "method": "GET",
       "path": ["nonexistent"],
       "user": "alice"
    }
    allow == false with input as in
}

user_is_employee {
 	users[input.user]
}

user_is_manager{
	u := users[input.user]
 	u.title != "salesperson"
}