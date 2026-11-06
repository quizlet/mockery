<?php
/**
 * Mockery
 *
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://github.com/padraic/mockery/blob/master/LICENSE
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to padraic@php.net so we can send you a copy immediately.
 *
 * @category   Mockery
 * @package    Mockery
 * @subpackage UnitTests
 * @copyright  Copyright (c) 2010 Pádraic Brady (http://blog.astrumfutura.com)
 * @license    http://github.com/padraic/mockery/blob/master/LICENSE New BSD License
 */

namespace Mockery\Loader;

use Mockery\Generator\MockConfiguration;
use Mockery\Generator\MockDefinition;
use PHPUnit\Framework\TestCase;

/**
 * Security expectations for RequireLoader.
 *
 * These tests fail while a temp path derived from uniqid() can be planted
 * before the write, while a failed write is still required, or while the
 * generated source is left where the process umask lets other users read it.
 */
class RequireLoaderSecurityTest extends TestCase
{
    private $directories = array();

    private $trackedSentinels = array();

    private $previousUmask;

    private $previousLoader;

    private $previousConstantsMap;

    private $loadStartedAt = 0;

    private $loadEndedAt = 0;

    protected function setUp()
    {
        $this->previousUmask = umask(0022);
        $this->previousLoader = \Mockery::getLoader();
        $this->previousConstantsMap = \Mockery::getConfiguration()->getConstantsMap();
    }

    protected function tearDown()
    {
        \Mockery::close();
        \Mockery::setLoader($this->previousLoader);
        \Mockery::getConfiguration()->setConstantsMap($this->previousConstantsMap);
        umask($this->previousUmask);

        foreach ($this->trackedSentinels as $directory => $sentinel) {
            foreach ($this->filesContaining($directory, $sentinel) as $path) {
                if (is_file($path) || is_link($path)) {
                    unlink($path);
                }
            }
        }

        foreach ($this->directories as $directory) {
            $this->removeDirectory($directory);
        }
    }

    /**
     * @test
     */
    public function testPrecreatedReadOnlyTempFileIsNotExecuted()
    {
        $directory = $this->makeStickyDirectory();
        $marker = $directory . '/attacker-ran';
        $payload = "<?php file_put_contents(" . var_export($marker, true) . ", 'executed');";
        $planted = $this->plantClockWindow($directory, function ($path) use ($payload) {
            if (file_put_contents($path, $payload) === false) {
                $this->fail('Could not plant ' . $path);
            }
            chmod($path, 0444);
        });

        $className = $this->freshClassName('MockerySecurityReadOnly');
        $included = $this->loadThroughRequireLoader($directory, $className, $this->classSource($className, 'readonly-sentinel'));

        $this->assertFalse(file_exists($marker), 'RequireLoader executed PHP from a precreated temp file');
        $this->assertPlantedFilesUntouched($planted, $payload);
        $this->assertTrue(class_exists($className, false), 'RequireLoader did not load the generated mock');
        $this->assertIncludedPathsAreExclusive($included, $planted);
    }

    /**
     * @test
     */
    public function testPrecreatedSymlinkDoesNotOverwriteAnotherFile()
    {
        $directory = $this->makeStickyDirectory();
        $victimDirectory = $this->makeStickyDirectory();
        $victim = $victimDirectory . '/victim.txt';
        $original = 'victim-original-content';
        file_put_contents($victim, $original);
        chmod($victim, 0644);

        $planted = $this->plantClockWindow($directory, function ($path) use ($victim) {
            if (!symlink($victim, $path)) {
                $this->fail('Could not plant symlink ' . $path);
            }
        });

        $className = $this->freshClassName('MockerySecuritySymlink');
        $included = $this->loadThroughRequireLoader($directory, $className, $this->classSource($className, 'symlink-sentinel'));

        clearstatcache(true);
        $this->assertSame(
            $original,
            file_get_contents($victim),
            'RequireLoader followed a precreated symlink and replaced another file'
        );
        $this->assertTrue(is_file($victim), 'RequireLoader removed the symlink target');
        foreach ($planted as $path) {
            if (!is_link($path) || readlink($path) !== $victim) {
                $this->fail('RequireLoader removed or replaced a precreated symlink: ' . $path);
            }
        }
        $this->assertTrue(class_exists($className, false), 'RequireLoader did not load the generated mock');
        foreach ($included as $path) {
            $this->assertNotSame(realpath($victim), realpath($path), 'RequireLoader loaded the symlink target ' . $path);
        }
        $this->assertIncludedPathsAreExclusive($included, $planted);
    }

    /**
     * @test
     */
    public function testTempMockSourceIsPrivateWhileItIsLoadedAndRemovedAfterwards()
    {
        $directory = $this->makeStickyDirectory();
        $record = $directory . '/mode-record';
        $className = $this->freshClassName('MockerySecurityMode');
        $sentinel = 'mode-sentinel-value';
        $source = "<?php file_put_contents("
            . var_export($record, true)
            . ", __FILE__ . \"\\n\" . (fileperms(__FILE__) & 0777));\n"
            . "class $className { const SECRET = " . var_export($sentinel, true) . "; }\n";

        $this->loadThroughRequireLoader($directory, $className, $source);

        $this->assertTrue(class_exists($className, false));
        $this->assertFileExists($record, 'Generated mock did not record the temp file mode while it was loaded');
        $recorded = file_get_contents($record);
        $lines = explode("\n", $recorded);
        $tempPath = $lines[0];
        $mode = isset($lines[1]) ? (int) $lines[1] : -1;

        $this->assertNotSame(
            realpath(__DIR__ . '/../../../library/Mockery/Loader/RequireLoader.php'),
            realpath($tempPath),
            'Mode probe ran from the loader file instead of a private temp file'
        );
        $this->assertSame(
            0,
            $mode & 0077,
            'Temp mock file was readable or writable by the group or others (mode ' . sprintf('%04o', $mode) . ')'
        );
        clearstatcache(true, $tempPath);
        $this->assertFalse(is_file($tempPath), 'Temp mock file was left behind at ' . $tempPath);
        $this->assertSame(array(), $this->filesContaining($directory, $sentinel));
    }

    /**
     * @test
     */
    public function testDocumentedSystemTempLoaderDoesNotLeaveGeneratedSecrets()
    {
        $sentinel = 'requireloader-security-sentinel-' . getmypid() . $this->freshClassName('');
        $directory = sys_get_temp_dir();
        $this->trackedSentinels[$directory] = $sentinel;

        $fixture = $this->freshClassName('RequireLoaderSecurityFixture');
        eval('class ' . $fixture . ' { public function reveal($token = ' . var_export($sentinel, true) . ') { return $token; } }');

        $overload = $this->freshClassName('RequireLoaderSecurityOverload');
        \Mockery::close();
        \Mockery::setLoader(new RequireLoader($directory));
        \Mockery::getConfiguration()->setConstantsMap(array(
            $overload => array('TOKEN' => $sentinel),
        ));

        $mock = \Mockery::mock($fixture);
        $overloaded = \Mockery::mock('overload:' . $overload);

        $this->assertInstanceOf($fixture, $mock);
        $this->assertInstanceOf($overload, $overloaded);
        $this->assertSame(array(), $this->filesContaining($directory, $sentinel));
    }

    private function loadThroughRequireLoader($directory, $className, $source)
    {
        $configuration = new MockConfiguration(array(), array(), array(), $className);
        $definition = new MockDefinition($configuration, $source);
        $loader = new RequireLoader($directory);
        $before = get_included_files();
        $this->loadStartedAt = microtime(true);

        $this->ignoreWarnings(function () use ($loader, $definition) {
            $loader->load($definition);
        });

        $this->loadEndedAt = microtime(true);

        return array_values(array_diff(get_included_files(), $before));
    }

    private function assertIncludedPathsAreExclusive(array $included, array $planted)
    {
        $plantedLookup = array();
        foreach ($planted as $path) {
            $plantedLookup[$path] = true;
        }

        $this->assertNotEmpty($included, 'RequireLoader did not require a temp file');
        foreach ($included as $path) {
            $this->assertArrayNotHasKey($path, $plantedLookup, 'RequireLoader required a precreated path ' . $path);
            $this->assertFalse(
                $this->isClockDerivedTempPath($path, $this->loadStartedAt, $this->loadEndedAt),
                'RequireLoader required a clock-derived temp path ' . $path
            );
        }
    }

    private function assertPlantedFilesUntouched(array $planted, $payload)
    {
        clearstatcache();
        $expectedSize = strlen($payload);
        foreach ($planted as $path) {
            if (!is_file($path) || is_link($path)) {
                $this->fail('Precreated temp file is missing: ' . $path);
            }
            if ((fileperms($path) & 0777) !== 0444 || filesize($path) !== $expectedSize || file_get_contents($path) !== $payload) {
                $this->fail('Precreated temp file was replaced or removed: ' . $path);
            }
        }
    }

    private function plantClockWindow($directory, $planter)
    {
        $spanUs = 40000;
        $probe = 1000;
        $probeStarted = microtime(true);
        for ($i = 0; $i < $probe; $i++) {
            $path = $directory . '/probe_' . $i;
            file_put_contents($path, 'x');
        }
        $rate = $probe / max(0.0001, microtime(true) - $probeStarted);
        for ($i = 0; $i < $probe; $i++) {
            unlink($directory . '/probe_' . $i);
        }

        $leadSeconds = ($spanUs / $rate) * 3 + 0.4;
        $start = microtime(true) + $leadSeconds;
        $second = (int) floor($start);
        $usec = (int) floor(($start - $second) * 1000000);
        if ($usec > 999999) {
            $second++;
            $usec = 0;
        }

        $paths = array();
        $remaining = $spanUs;
        while ($remaining > 0) {
            $path = sprintf('%s/Mockery_%08x%05x.php', $directory, $second, $usec);
            $planter($path);
            $paths[] = $path;
            $usec++;
            $remaining--;
            if ($usec > 999999) {
                $usec = 0;
                $second++;
            }
        }

        $windowStart = $start;
        if (microtime(true) < $windowStart) {
            while (microtime(true) < $windowStart) {
            }
        }

        return $paths;
    }

    private function isClockDerivedTempPath($path, $notBefore, $notAfter)
    {
        $name = basename($path);
        if (!preg_match('/^Mockery_([0-9a-f]{8})([0-9a-f]{5})\.php$/', $name, $matches)) {
            return false;
        }

        $decoded = hexdec($matches[1]) + (hexdec($matches[2]) / 1000000);
        return $decoded >= ($notBefore - 0.002) && $decoded <= ($notAfter + 0.002);
    }

    private function classSource($className, $sentinel)
    {
        return "<?php class $className { const SECRET = " . var_export($sentinel, true) . "; }\n";
    }

    private function freshClassName($prefix)
    {
        $micro = microtime(false);
        $micro = str_replace(array(' ', '.'), '', $micro);
        return $prefix . $micro . getmypid();
    }

    private function makeStickyDirectory()
    {
        $directory = sys_get_temp_dir() . '/mockery-requireloader-' . getmypid() . '-' . str_replace(array(' ', '.'), '', microtime(false));
        if (!mkdir($directory, 01777) && !is_dir($directory)) {
            $this->fail('Could not create ' . $directory);
        }
        chmod($directory, 01777);
        $this->directories[] = $directory;
        return $directory;
    }

    private function filesContaining($directory, $sentinel)
    {
        $paths = glob($directory . '/Mockery*');
        if ($paths === false) {
            return array();
        }

        $matches = array();
        foreach ($paths as $path) {
            if (is_link($path) || !is_file($path)) {
                continue;
            }
            $contents = file_get_contents($path);
            if ($contents !== false && strpos($contents, $sentinel) !== false) {
                $matches[] = $path;
            }
        }

        return $matches;
    }

    private function ignoreWarnings($callback)
    {
        set_error_handler(function ($severity) {
            if ($severity === E_WARNING || $severity === E_NOTICE || $severity === E_USER_WARNING || $severity === E_USER_NOTICE) {
                return true;
            }
            return false;
        });

        try {
            return $callback();
        } finally {
            restore_error_handler();
        }
    }

    private function removeDirectory($directory)
    {
        if (!is_dir($directory)) {
            return;
        }

        $items = scandir($directory);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $directory . '/' . $item;
            if (is_link($path) || is_file($path)) {
                unlink($path);
            } elseif (is_dir($path)) {
                $this->removeDirectory($path);
            }
        }

        rmdir($directory);
    }
}
