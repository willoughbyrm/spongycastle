package java.math.test;

import org.spongycastle.util.test.Test;
import org.spongycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new BigIntegerTest()
    };

    public static void main(
        String[]    args)
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            System.out.println(result);
        }
    }
}
