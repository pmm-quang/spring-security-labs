package org.example.exception;

public class InvalidException extends RuntimeException{
    public InvalidException(String message) {
        super(String.format(message));
    }
}
