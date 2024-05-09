package com.abdohalim.springbootsecurity.Todo;


import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
public class TodoResource {
    public static  List<Todo> todos=new ArrayList<Todo>();
    static {
        todos.add(new Todo("abdo","spring"));
        todos.add(new Todo("abdo","Python"));

    }

    @GetMapping("/Todos")
    public List<Todo> retriveAllTodos(){
        return todos;
    }
    @PostMapping("/user/{username}/todo")
    public void addTodo(@PathVariable String username, @RequestBody Todo todo){

        todos.add(todo);
    }


}
record  Todo(String username,String description){};
