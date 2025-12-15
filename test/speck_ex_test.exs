defmodule SpeckExTest do
  use ExUnit.Case
  doctest SpeckEx

  test "greets the world" do
    assert SpeckEx.hello() == :world
  end
end
